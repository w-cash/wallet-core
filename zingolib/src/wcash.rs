//! Wcash Testnet identity and application runtime.
//!
//! This runtime calls the Wcash wallet backend directly and stays separate
//! from Zingo's Zcash [`crate::config::ChainType`] and
//! [`crate::lightclient::LightClient`]. Applications retain the mnemonic or
//! master seed and supply it while creating, restoring, or signing.
//!
//! Run the opt-in public endpoint attestation with:
//! `cargo test -p zingolib --lib wcash::tests::live_testnet_endpoint_attests -- --ignored --exact`.

use std::path::{Path, PathBuf};

use secrecy::SecretVec;
use serde::Serialize;
use thiserror::Error;
use wcash_wallet::{
    AttestedWcashClient, TransferRecipient, WalletNetwork, WalletRpcError, WalletServiceError,
    active_pending_signed_transactions, create_signed_coinbase_shielding, create_signed_transfer,
    initialize_wallet, inspect_signed_transaction, inspect_wallet, pending_signed_transactions,
    synchronize_wallet_cancellable, wallet_balance,
};

pub use wcash_wallet::{
    BlockRef, BroadcastDisposition, BroadcastResult, InitializedWallet,
    PendingSignedTransactionPage, SignedTransaction, StoredSignedTransaction, WalletBalanceSummary,
    WalletInfo, WalletSyncCancellation,
};

const WCASH_TESTNET_TICKER: &str = "TWC";
const WCASH_TESTNET_GENESIS_DISPLAY: &str =
    "0271b5b0a10b2838f43cccdec9ca2f72aa72a7c103830082bac8f82f47f0593a";
const WCASH_TESTNET_STORAGE_NAMESPACE: &str = "wcashtestnet-v5";
const PUBLIC_CONFIRMATIONS: u32 = 100;
const DEFAULT_EXPIRY_DELTA: u32 = 40;
// A Wcash input reservation must not outlive the exact transaction that owns
// it. At a synchronized tip equal to the transaction expiry height, that
// transaction cannot enter the next block and the input can be selected for a
// replacement without creating two simultaneously valid transactions.
const DEFAULT_LOCK_FOR_BLOCKS: u32 = DEFAULT_EXPIRY_DELTA;
const DEFAULT_COINBASE_INPUTS: usize = 100;
const ALLOW_UNSAFE_REGTEST_CONFIRMATIONS: bool = false;

/// The Wcash Testnet identity accepted by this release.
///
/// Every runtime operation selects this frozen Testnet identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WcashTestnet;

impl WcashTestnet {
    /// Returns the Wcash backend network selected by this profile.
    pub const fn network(self) -> WalletNetwork {
        WalletNetwork::Testnet
    }

    /// Returns the ticker for valueless test funds.
    pub const fn ticker(self) -> &'static str {
        WCASH_TESTNET_TICKER
    }

    /// Returns the frozen genesis block identifier in display byte order.
    pub const fn genesis_hash_display(self) -> &'static str {
        WCASH_TESTNET_GENESIS_DISPLAY
    }

    /// Returns the frozen genesis block identifier in internal byte order.
    pub fn genesis_hash(self) -> [u8; 32] {
        self.network().genesis_hash()
    }

    /// Returns the Wcash transaction and signature domain.
    pub fn branch_id(self) -> u32 {
        self.network().branch_id().into()
    }

    /// Returns the wallet and block-cache namespace.
    pub const fn storage_namespace(self) -> &'static str {
        WCASH_TESTNET_STORAGE_NAMESPACE
    }
}

/// A shielded payment passed to [`WcashTestnetRuntime::send`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WcashTestnetPayment {
    /// Canonical Wcash Unified Address.
    pub address: String,
    /// Amount in zatoshis.
    pub amount_zat: u64,
    /// Raw memo bytes, bounded and checked by the backend.
    pub memo: Vec<u8>,
}

impl From<WcashTestnetPayment> for TransferRecipient {
    fn from(payment: WcashTestnetPayment) -> Self {
        Self {
            address: payment.address,
            amount_zat: payment.amount_zat,
            memo: payment.memo,
        }
    }
}

/// The receiving addresses for one Wcash Testnet account.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WcashTestnetReceivers {
    /// Canonical Unified Address for Ironwood receipts.
    pub ironwood_address: String,
    /// Deterministic P2PKH address for transparent coinbase payouts.
    pub transparent_coinbase_address: String,
}

impl From<WalletInfo> for WcashTestnetReceivers {
    fn from(info: WalletInfo) -> Self {
        Self {
            ironwood_address: info.address,
            transparent_coinbase_address: info.transparent_coinbase_address,
        }
    }
}

/// Errors from the Wcash Testnet runtime boundary.
#[derive(Debug, Error)]
pub enum WcashTestnetRuntimeError {
    /// Endpoint connection, attestation, or broadcast failure.
    #[error(transparent)]
    Rpc(#[from] WalletRpcError),
    /// Persistent wallet operation failure.
    #[error(transparent)]
    Wallet(#[from] WalletServiceError),
    /// The create or restore target already contains a wallet account.
    #[error("the wallet path already contains an initialized Wcash account")]
    WalletAlreadyInitialized,
    /// Stored signed bytes had invalid hexadecimal encoding.
    #[error("the signed transaction encoding is invalid")]
    InvalidSignedTransactionHex(#[source] hex::FromHexError),
    /// Signed transaction metadata did not describe the exact stored bytes.
    #[error("the signed transaction metadata does not match its serialized bytes")]
    SignedTransactionMetadataMismatch,
}

/// A network-attested session for one persistent Wcash Testnet wallet.
///
/// Online operations are serialized through the contained client. Wallet
/// synchronization is a restartable one-shot call. Balance reads fail closed
/// while the backend's durable transparent recovery marker is incomplete.
#[derive(Debug)]
pub struct WcashTestnetRuntime {
    wallet_path: PathBuf,
    client: AttestedWcashClient,
}

impl WcashTestnetRuntime {
    /// Creates one new account near the current attested Testnet tip.
    pub async fn create(
        endpoint: &str,
        wallet_path: impl AsRef<Path>,
        master_seed: &SecretVec<u8>,
    ) -> Result<(Self, InitializedWallet), WcashTestnetRuntimeError> {
        Self::initialize(endpoint, wallet_path, master_seed, None).await
    }

    /// Restores one account from an explicit Testnet birthday height.
    pub async fn restore(
        endpoint: &str,
        wallet_path: impl AsRef<Path>,
        master_seed: &SecretVec<u8>,
        birthday_height: u32,
    ) -> Result<(Self, InitializedWallet), WcashTestnetRuntimeError> {
        Self::initialize(endpoint, wallet_path, master_seed, Some(birthday_height)).await
    }

    /// Opens an existing account and attests its Testnet endpoint.
    ///
    /// Inspection is read-only and uses public account metadata. The caller
    /// supplies spending authority only to [`Self::send`].
    pub async fn open(
        endpoint: &str,
        wallet_path: impl AsRef<Path>,
    ) -> Result<(Self, WalletInfo), WcashTestnetRuntimeError> {
        let wallet_path = wallet_path.as_ref().to_path_buf();
        let info = Self::inspect(&wallet_path)?;
        let runtime = Self::connect(endpoint, wallet_path).await?;
        Ok((runtime, info))
    }

    /// Reads public account metadata through a read-only database handle.
    pub fn inspect(wallet_path: impl AsRef<Path>) -> Result<WalletInfo, WcashTestnetRuntimeError> {
        inspect_wallet(wallet_path, WcashTestnet.network()).map_err(Into::into)
    }

    /// Returns the database path owned by this runtime.
    pub fn wallet_path(&self) -> &Path {
        &self.wallet_path
    }

    /// Synchronizes through bounded, cancellable, durable backend batches.
    pub async fn sync(
        &mut self,
        cancellation: &WalletSyncCancellation,
    ) -> Result<WalletBalanceSummary, WcashTestnetRuntimeError> {
        synchronize_wallet_cancellable(
            &mut self.client,
            &self.wallet_path,
            WcashTestnet.network(),
            wcash_wallet::MAX_SYNC_BATCH_SIZE,
            cancellation,
        )
        .await
        .map_err(Into::into)
    }

    /// Reads the current fail-closed pool-separated balance.
    pub fn balance(&self) -> Result<WalletBalanceSummary, WcashTestnetRuntimeError> {
        wallet_balance(&self.wallet_path, WcashTestnet.network()).map_err(Into::into)
    }

    /// Reads the account's canonical receiving addresses.
    pub fn receive(&self) -> Result<WcashTestnetReceivers, WcashTestnetRuntimeError> {
        Self::inspect(&self.wallet_path).map(Into::into)
    }

    /// Builds, proves, signs, and persists one Ironwood transfer.
    ///
    /// The returned bytes remain local until [`Self::broadcast`] is called.
    /// The backend enforces the public confirmation floor and exact-tip policy.
    pub async fn send(
        &mut self,
        master_seed: &SecretVec<u8>,
        payments: Vec<WcashTestnetPayment>,
    ) -> Result<SignedTransaction, WcashTestnetRuntimeError> {
        let recipients = payments.into_iter().map(Into::into).collect();
        create_signed_transfer(
            &mut self.client,
            &self.wallet_path,
            WcashTestnet.network(),
            master_seed,
            recipients,
            PUBLIC_CONFIRMATIONS,
            ALLOW_UNSAFE_REGTEST_CONFIRMATIONS,
            DEFAULT_EXPIRY_DELTA,
            DEFAULT_LOCK_FOR_BLOCKS,
        )
        .await
        .map_err(Into::into)
    }

    /// Shields mature transparent coinbase outputs into Ironwood.
    ///
    /// The backend selects at most its reviewed input cap and enforces coinbase
    /// maturity. The returned bytes use the same [`Self::broadcast`] path as a
    /// regular transfer.
    pub async fn shield_coinbase(
        &mut self,
        master_seed: &SecretVec<u8>,
    ) -> Result<SignedTransaction, WcashTestnetRuntimeError> {
        create_signed_coinbase_shielding(
            &mut self.client,
            &self.wallet_path,
            WcashTestnet.network(),
            master_seed,
            DEFAULT_COINBASE_INPUTS,
            DEFAULT_EXPIRY_DELTA,
            DEFAULT_LOCK_FOR_BLOCKS,
        )
        .await
        .map_err(Into::into)
    }

    /// Broadcasts the exact bytes returned by [`Self::send`].
    pub async fn broadcast(
        &mut self,
        signed: &SignedTransaction,
    ) -> Result<BroadcastResult, WcashTestnetRuntimeError> {
        let raw = validate_signed_bytes(
            &signed.txid,
            &signed.branch_id,
            signed.expiry_height,
            &signed.raw_transaction_hex,
        )?;
        self.client
            .broadcast_raw_transaction(raw)
            .await
            .map_err(Into::into)
    }

    /// Lists signed bytes that can be recovered after an interrupted app call.
    pub fn pending_transactions(
        &self,
        after_row_id: Option<u64>,
        limit: usize,
    ) -> Result<PendingSignedTransactionPage, WcashTestnetRuntimeError> {
        pending_signed_transactions(
            &self.wallet_path,
            WcashTestnet.network(),
            after_row_id,
            limit,
        )
        .map_err(Into::into)
    }

    /// Lists only transactions that remain valid at an internally attested
    /// exact wallet tip.
    ///
    /// `expected_tip` is an equality precondition for continuation pages, not
    /// filtering authority. The backend always derives the canonical height
    /// and hash from one locked SQLite snapshot.
    pub fn active_pending_transactions(
        &self,
        expected_tip: Option<BlockRef>,
        after_row_id: Option<u64>,
        limit: usize,
    ) -> Result<PendingSignedTransactionPage, WcashTestnetRuntimeError> {
        active_pending_signed_transactions(
            &self.wallet_path,
            WcashTestnet.network(),
            expected_tip,
            after_row_id,
            limit,
        )
        .map_err(Into::into)
    }

    /// Broadcasts exact signed bytes recovered from the wallet database.
    pub async fn broadcast_pending(
        &mut self,
        signed: &StoredSignedTransaction,
    ) -> Result<BroadcastResult, WcashTestnetRuntimeError> {
        let raw = validate_signed_bytes(
            &signed.txid,
            &signed.branch_id,
            signed.expiry_height,
            &signed.raw_transaction_hex,
        )?;
        self.client
            .broadcast_raw_transaction(raw)
            .await
            .map_err(Into::into)
    }

    async fn initialize(
        endpoint: &str,
        wallet_path: impl AsRef<Path>,
        master_seed: &SecretVec<u8>,
        birthday_height: Option<u32>,
    ) -> Result<(Self, InitializedWallet), WcashTestnetRuntimeError> {
        let wallet_path = wallet_path.as_ref().to_path_buf();
        let mut runtime = Self::connect(endpoint, wallet_path).await?;
        let initialized = initialize_wallet(
            &mut runtime.client,
            &runtime.wallet_path,
            WcashTestnet.network(),
            master_seed,
            birthday_height,
        )
        .await?;
        if initialized.created {
            Ok((runtime, initialized))
        } else {
            Err(WcashTestnetRuntimeError::WalletAlreadyInitialized)
        }
    }

    async fn connect(
        endpoint: &str,
        wallet_path: PathBuf,
    ) -> Result<Self, WcashTestnetRuntimeError> {
        let client = AttestedWcashClient::connect(endpoint, WcashTestnet.network()).await?;
        Ok(Self {
            wallet_path,
            client,
        })
    }
}

fn validate_signed_bytes(
    expected_txid: &str,
    branch_id: &str,
    expiry_height: u32,
    raw_transaction_hex: &str,
) -> Result<Vec<u8>, WcashTestnetRuntimeError> {
    if branch_id != WcashTestnet.network().branch_id_hex() {
        return Err(WcashTestnetRuntimeError::SignedTransactionMetadataMismatch);
    }
    let raw = hex::decode(raw_transaction_hex)
        .map_err(WcashTestnetRuntimeError::InvalidSignedTransactionHex)?;
    let transaction = inspect_signed_transaction(&raw, WcashTestnet.network())?;
    let actual_expiry_height = u32::from(transaction.expiry_height());
    if transaction.txid().to_string() != expected_txid || actual_expiry_height != expiry_height {
        return Err(WcashTestnetRuntimeError::SignedTransactionMetadataMismatch);
    }
    Ok(raw)
}

#[cfg(test)]
mod tests {
    use zcash_protocol::consensus::BranchId;

    use super::*;

    const WCASH_TESTNET_BRANCH_ID: u32 = 0xb3cf_d27e;
    const ZCASH_TESTNET_STORAGE_NAMESPACE: &str = "testnet3";
    const ZCASH_TICKER: &str = "ZEC";
    const TEST_ACCOUNT_ID: &str = "account";
    const TEST_BIRTHDAY_HEIGHT: u32 = 1;
    const TEST_IRONWOOD_ADDRESS: &str = "utest1example";
    const TEST_TRANSPARENT_ADDRESS: &str = "tmExample";
    const PUBLIC_TESTNET_ENDPOINT: &str = "https://wallet-testnet.wcashexplorer.com:443";
    const MASTER_SEED_BYTES: usize = 32;
    const EMPTY_SEED_BYTE: u8 = 0;
    const PRIVATE_FILE_MODE: u32 = 0o600;
    const FILE_MODE_MASK: u32 = 0o777;
    const IRONWOOD_TESTNET_PREFIX: &str = "wutest1";
    const TRANSPARENT_TESTNET_PREFIX: &str = "WT";

    #[test]
    fn profile_matches_the_frozen_wcash_testnet_identity() {
        let profile = WcashTestnet;

        assert_eq!(profile.network(), WalletNetwork::Testnet);
        assert_eq!(profile.ticker(), WCASH_TESTNET_TICKER);
        assert_eq!(
            profile.genesis_hash_display(),
            WCASH_TESTNET_GENESIS_DISPLAY
        );
        assert_eq!(profile.branch_id(), WCASH_TESTNET_BRANCH_ID);
        assert_eq!(profile.storage_namespace(), WCASH_TESTNET_STORAGE_NAMESPACE);
    }

    #[test]
    fn profile_is_disjoint_from_zcash_testnet() {
        let profile = WcashTestnet;

        assert_ne!(profile.ticker(), ZCASH_TICKER);
        assert_ne!(profile.storage_namespace(), ZCASH_TESTNET_STORAGE_NAMESPACE);
        assert_ne!(profile.branch_id(), u32::from(BranchId::Nu6_3));
    }

    #[test]
    fn receive_addresses_come_from_seedless_wallet_metadata() {
        let info = WalletInfo {
            account_id: TEST_ACCOUNT_ID.to_owned(),
            birthday_height: TEST_BIRTHDAY_HEIGHT,
            address: TEST_IRONWOOD_ADDRESS.to_owned(),
            transparent_coinbase_address: TEST_TRANSPARENT_ADDRESS.to_owned(),
        };

        assert_eq!(
            WcashTestnetReceivers::from(info),
            WcashTestnetReceivers {
                ironwood_address: TEST_IRONWOOD_ADDRESS.to_owned(),
                transparent_coinbase_address: TEST_TRANSPARENT_ADDRESS.to_owned(),
            }
        );
    }

    #[test]
    fn coinbase_shielding_uses_the_reviewed_backend_cap() {
        assert_eq!(
            DEFAULT_COINBASE_INPUTS,
            wcash_wallet::MAX_COINBASE_SHIELDING_INPUTS
        );
    }

    #[test]
    fn wcash_input_reservation_ends_at_the_exact_transaction_expiry_tip() {
        const TRANSACTION_TARGET_HEIGHT: u32 = 1_000;

        let transaction_expiry_height = TRANSACTION_TARGET_HEIGHT
            .checked_add(DEFAULT_EXPIRY_DELTA)
            .unwrap();
        let input_lock_expiry_height = TRANSACTION_TARGET_HEIGHT
            .checked_add(DEFAULT_LOCK_FOR_BLOCKS)
            .unwrap();
        let exact_synchronized_tip = transaction_expiry_height;
        let next_transaction_target = exact_synchronized_tip.checked_add(1).unwrap();

        assert_eq!(input_lock_expiry_height, transaction_expiry_height);
        assert!(
            input_lock_expiry_height < next_transaction_target,
            "the Wcash input must be selectable for the first block after its previous transaction expired"
        );
    }

    #[test]
    fn inspecting_a_missing_wallet_does_not_create_it() {
        let directory = tempfile::tempdir().unwrap();
        let wallet_path = directory.path().join("wallet.db");

        let error = WcashTestnetRuntime::inspect(&wallet_path).unwrap_err();

        assert!(matches!(
            error,
            WcashTestnetRuntimeError::Wallet(WalletServiceError::WalletDatabaseMissing)
        ));
        assert!(!wallet_path.exists());
    }

    #[tokio::test]
    #[ignore = "requires the public Wcash Testnet endpoint"]
    async fn live_testnet_endpoint_attests() {
        use rand::RngCore;

        let directory = tempfile::tempdir().unwrap();
        let wallet_path = directory.path().join("wallet.db");
        let mut seed_bytes = vec![EMPTY_SEED_BYTE; MASTER_SEED_BYTES];
        rand::rngs::OsRng.fill_bytes(&mut seed_bytes);
        let master_seed = SecretVec::new(seed_bytes);
        let (mut runtime, initialized) = WcashTestnetRuntime::restore(
            PUBLIC_TESTNET_ENDPOINT,
            &wallet_path,
            &master_seed,
            TEST_BIRTHDAY_HEIGHT,
        )
        .await
        .unwrap();

        assert!(initialized.created);
        assert!(initialized.address.starts_with(IRONWOOD_TESTNET_PREFIX));
        assert!(
            initialized
                .transparent_coinbase_address
                .starts_with(TRANSPARENT_TESTNET_PREFIX)
        );

        let cancellation = WalletSyncCancellation::new();
        let synchronized = runtime.sync(&cancellation).await.unwrap();
        assert!(synchronized.synchronized);
        assert_eq!(runtime.balance().unwrap(), synchronized);
        let active = runtime.active_pending_transactions(None, None, 1).unwrap();
        assert_eq!(
            active.exact_tip.map(|tip| tip.height),
            Some(synchronized.chain_tip_height)
        );
        assert!(active.transactions.is_empty());
        assert_eq!(active.next_after_row_id, None);

        drop(runtime);
        let (reopened, info) = WcashTestnetRuntime::open(PUBLIC_TESTNET_ENDPOINT, &wallet_path)
            .await
            .unwrap();
        let receivers = reopened.receive().unwrap();

        assert_eq!(info.account_id, initialized.account_id);
        assert_eq!(receivers.ironwood_address, initialized.address);
        assert_eq!(
            receivers.transparent_coinbase_address,
            initialized.transparent_coinbase_address
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mode = std::fs::metadata(&wallet_path)
                .unwrap()
                .permissions()
                .mode()
                & FILE_MODE_MASK;
            assert_eq!(mode, PRIVATE_FILE_MODE);
        }
    }
}
