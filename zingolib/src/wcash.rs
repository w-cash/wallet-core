//! Wcash identity and application runtimes.
//!
//! This runtime calls the Wcash wallet backend directly and stays separate
//! from Zingo's Zcash [`crate::config::ChainType`] and
//! [`crate::lightclient::LightClient`]. Applications retain the mnemonic or
//! master seed and supply it while creating, restoring, or signing.
//! The local Regtest runtime is compiled only with the default-off `regtest`
//! feature.
//!
//! Run the opt-in public endpoint attestation with:
//! `cargo test -p zingolib --lib wcash::tests::live_testnet_endpoint_attests -- --ignored --exact`.

use std::path::{Path, PathBuf};

use secrecy::SecretVec;
use serde::Serialize;
use thiserror::Error;
#[cfg(feature = "regtest")]
use wcash_wallet::wallet_balance_with_confirmations;
use wcash_wallet::{
    AttestedWcashClient, TransferRecipient, WalletNetwork, WalletRpcError, WalletServiceError,
    active_pending_signed_transactions, broadcast_calculated_transaction,
    calculate_staged_transaction, cancel_staged_transaction, confirmed_transaction_history,
    confirmed_transaction_summary_history, create_signed_coinbase_shielding,
    create_signed_transfer, initialize_wallet, inspect_signed_transaction, inspect_wallet,
    pending_signed_transactions, propose_coinbase_shielding_offline, propose_transfer_offline,
    synchronize_wallet_cancellable, verify_wallet_seed, wallet_balance,
};

pub use wcash_wallet::{
    BlockRef, BroadcastDisposition, BroadcastResult, CalculatedTransaction, ConfirmedTransaction,
    ConfirmedTransactionDirection, ConfirmedTransactionHistory, ConfirmedTransactionKind,
    ConfirmedTransactionSummary, ConfirmedTransactionSummaryHistory, InitializedWallet,
    MAX_CONFIRMED_TRANSACTION_HISTORY_SIZE, MAX_PENDING_TRANSACTION_PAGE_SIZE,
    PendingSignedTransactionPage, SignedTransaction, StagedTransactionProposal,
    StoredSignedTransaction, WalletAddressError, WalletBalanceSummary, WalletInfo,
    WalletSyncCancellation,
};

const WCASH_TESTNET_TICKER: &str = "TWC";
const WCASH_TESTNET_NETWORK_LABEL: &str = "Wcash Testnet";
const WCASH_TESTNET_GENESIS_DISPLAY: &str =
    "0271b5b0a10b2838f43cccdec9ca2f72aa72a7c103830082bac8f82f47f0593a";
const WCASH_TESTNET_STORAGE_NAMESPACE: &str = "wcashtestnet-v5";
const WCASH_TESTNET_DEFAULT_ENDPOINT: &str = "https://wallet-testnet.wcashexplorer.com:443";
const PUBLIC_CONFIRMATIONS: u32 = 100;
#[cfg(feature = "regtest")]
const REGTEST_CONFIRMATIONS: u32 = 1;
const DEFAULT_EXPIRY_DELTA: u32 = 40;
// A Wcash input reservation must not outlive the exact transaction that owns
// it. At a synchronized tip equal to the transaction expiry height, that
// transaction cannot enter the next block and the input can be selected for a
// replacement without creating two simultaneously valid transactions.
const DEFAULT_LOCK_FOR_BLOCKS: u32 = DEFAULT_EXPIRY_DELTA;
const DEFAULT_COINBASE_INPUTS: usize = 100;
const ALLOW_UNSAFE_REGTEST_CONFIRMATIONS: bool = false;
#[cfg(feature = "regtest")]
const WCASH_REGTEST_TICKER: &str = "TWC";
#[cfg(feature = "regtest")]
const WCASH_REGTEST_NETWORK_LABEL: &str = "Wcash Regtest";
#[cfg(feature = "regtest")]
const WCASH_REGTEST_GENESIS_DISPLAY: &str =
    "70bf0bab17eff361a6331bb825b3b7253c8c96ff96407f948161d2912658bb1c";
#[cfg(feature = "regtest")]
const WCASH_REGTEST_STORAGE_NAMESPACE: &str = "wcashregtest-v5";
#[cfg(feature = "regtest")]
const WCASH_REGTEST_DEFAULT_ENDPOINT: &str = "http://127.0.0.1:48234";
#[cfg(feature = "regtest")]
const ALLOW_UNSAFE_LOCAL_CONFIRMATIONS: bool = true;

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

    /// Returns the network label displayed by applications.
    pub const fn network_label(self) -> &'static str {
        WCASH_TESTNET_NETWORK_LABEL
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

    /// Returns the public compact-block endpoint for this profile.
    pub const fn default_endpoint(self) -> &'static str {
        WCASH_TESTNET_DEFAULT_ENDPOINT
    }

    /// Checks that an encoded recipient is canonical for Wcash Testnet and can receive Ironwood.
    pub fn validate_recipient(self, address: &str) -> Result<(), WalletAddressError> {
        wcash_wallet::decode_recipient(address, self.network()).map(drop)
    }

    /// Confirms that a master seed controls the stored Testnet account.
    pub fn verify_seed(
        self,
        wallet_path: impl AsRef<Path>,
        master_seed: &SecretVec<u8>,
    ) -> Result<(), WcashTestnetRuntimeError> {
        verify_wallet_seed(wallet_path, self.network(), master_seed).map_err(Into::into)
    }

    /// Returns the spend confirmation floor for this public network.
    pub const fn required_confirmations(self) -> u32 {
        PUBLIC_CONFIRMATIONS
    }
}

/// The isolated Wcash Regtest identity used by local QA builds.
#[cfg(feature = "regtest")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WcashRegtest;

#[cfg(feature = "regtest")]
impl WcashRegtest {
    /// Returns the Wcash backend network selected by this profile.
    pub const fn network(self) -> WalletNetwork {
        WalletNetwork::Regtest
    }

    /// Returns the ticker for valueless local funds.
    pub const fn ticker(self) -> &'static str {
        WCASH_REGTEST_TICKER
    }

    /// Returns the network label displayed by QA applications.
    pub const fn network_label(self) -> &'static str {
        WCASH_REGTEST_NETWORK_LABEL
    }

    /// Returns the frozen local genesis block identifier in display byte order.
    pub const fn genesis_hash_display(self) -> &'static str {
        WCASH_REGTEST_GENESIS_DISPLAY
    }

    /// Returns the frozen local genesis block identifier in internal byte order.
    pub fn genesis_hash(self) -> [u8; 32] {
        self.network().genesis_hash()
    }

    /// Returns the local transaction and signature domain.
    pub fn branch_id(self) -> u32 {
        self.network().branch_id().into()
    }

    /// Returns the local wallet and block-cache namespace.
    pub const fn storage_namespace(self) -> &'static str {
        WCASH_REGTEST_STORAGE_NAMESPACE
    }

    /// Returns the fixed local QA endpoint for this profile.
    pub const fn default_endpoint(self) -> &'static str {
        WCASH_REGTEST_DEFAULT_ENDPOINT
    }

    /// Returns the one-block spend confirmation floor used by local QA.
    pub const fn required_confirmations(self) -> u32 {
        REGTEST_CONFIRMATIONS
    }

    /// Checks that an encoded recipient is canonical for Wcash Regtest and can receive Ironwood.
    pub fn validate_recipient(self, address: &str) -> Result<(), WalletAddressError> {
        wcash_wallet::decode_recipient(address, self.network()).map(drop)
    }

    /// Confirms that a master seed controls the stored Regtest account.
    pub fn verify_seed(
        self,
        wallet_path: impl AsRef<Path>,
        master_seed: &SecretVec<u8>,
    ) -> Result<(), WcashRegtestRuntimeError> {
        verify_wallet_seed(wallet_path, self.network(), master_seed).map_err(Into::into)
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

/// A shielded payment passed to [`WcashRegtestRuntime::send`].
#[cfg(feature = "regtest")]
pub type WcashRegtestPayment = WcashTestnetPayment;

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

/// The receiving addresses for one local Wcash Regtest account.
#[cfg(feature = "regtest")]
pub type WcashRegtestReceivers = WcashTestnetReceivers;

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

/// Errors from the local Wcash Regtest runtime boundary.
#[cfg(feature = "regtest")]
pub type WcashRegtestRuntimeError = WcashTestnetRuntimeError;

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
        Self::read_balance(&self.wallet_path)
    }

    /// Reads a wallet balance without opening a network session.
    pub fn read_balance(
        wallet_path: impl AsRef<Path>,
    ) -> Result<WalletBalanceSummary, WcashTestnetRuntimeError> {
        wallet_balance(wallet_path, WcashTestnet.network()).map_err(Into::into)
    }

    /// Reads newest-first confirmed transaction metadata at the exact synchronized tip.
    pub fn confirmed_transactions(
        &self,
        limit: usize,
    ) -> Result<ConfirmedTransactionHistory, WcashTestnetRuntimeError> {
        Self::read_confirmed_transactions(&self.wallet_path, limit)
    }

    /// Reads confirmed transaction metadata without opening a network session.
    pub fn read_confirmed_transactions(
        wallet_path: impl AsRef<Path>,
        limit: usize,
    ) -> Result<ConfirmedTransactionHistory, WcashTestnetRuntimeError> {
        confirmed_transaction_history(wallet_path, WcashTestnet.network(), limit)
            .map_err(Into::into)
    }

    /// Reads confirmed transaction metadata and wallet-display values.
    pub fn confirmed_transaction_summaries(
        &self,
        limit: usize,
    ) -> Result<ConfirmedTransactionSummaryHistory, WcashTestnetRuntimeError> {
        Self::read_confirmed_transaction_summaries(&self.wallet_path, limit)
    }

    /// Reads confirmed transaction metadata and values from wallet storage.
    pub fn read_confirmed_transaction_summaries(
        wallet_path: impl AsRef<Path>,
        limit: usize,
    ) -> Result<ConfirmedTransactionSummaryHistory, WcashTestnetRuntimeError> {
        confirmed_transaction_summary_history(wallet_path, WcashTestnet.network(), limit)
            .map_err(Into::into)
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

    /// Selects and locks one Ironwood transfer using public wallet state.
    pub fn propose_send(
        wallet_path: impl AsRef<Path>,
        payments: Vec<WcashTestnetPayment>,
    ) -> Result<StagedTransactionProposal, WcashTestnetRuntimeError> {
        propose_transfer_offline(
            wallet_path,
            WcashTestnet.network(),
            payments.into_iter().map(Into::into).collect(),
            PUBLIC_CONFIRMATIONS,
            ALLOW_UNSAFE_REGTEST_CONFIRMATIONS,
            DEFAULT_EXPIRY_DELTA,
            DEFAULT_LOCK_FOR_BLOCKS,
        )
        .map_err(Into::into)
    }

    /// Selects and locks mature transparent coinbase outputs.
    pub fn propose_shield_coinbase(
        wallet_path: impl AsRef<Path>,
    ) -> Result<StagedTransactionProposal, WcashTestnetRuntimeError> {
        propose_coinbase_shielding_offline(
            wallet_path,
            WcashTestnet.network(),
            DEFAULT_COINBASE_INPUTS,
            DEFAULT_EXPIRY_DELTA,
            DEFAULT_LOCK_FOR_BLOCKS,
        )
        .map_err(Into::into)
    }

    /// Signs the exact staged proposal using the local wallet state.
    pub fn calculate(
        wallet_path: impl AsRef<Path>,
        master_seed: &SecretVec<u8>,
        staged: &StagedTransactionProposal,
    ) -> Result<CalculatedTransaction, WcashTestnetRuntimeError> {
        calculate_staged_transaction(wallet_path, WcashTestnet.network(), master_seed, staged)
            .map_err(Into::into)
    }

    /// Releases the input locks held by an abandoned Testnet proposal.
    pub fn cancel(
        wallet_path: impl AsRef<Path>,
        staged: &StagedTransactionProposal,
    ) -> Result<(), WcashTestnetRuntimeError> {
        cancel_staged_transaction(wallet_path, WcashTestnet.network(), staged).map_err(Into::into)
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

    /// Revalidates and broadcasts the exact transaction returned by [`Self::calculate`].
    pub async fn broadcast_calculated(
        &mut self,
        calculated: &CalculatedTransaction,
    ) -> Result<BroadcastResult, WcashTestnetRuntimeError> {
        broadcast_calculated_transaction(&mut self.client, calculated)
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

    /// Lists transactions valid at the exact wallet tip through a read-only local session.
    pub fn read_active_pending_transactions(
        wallet_path: impl AsRef<Path>,
        expected_tip: Option<BlockRef>,
        after_row_id: Option<u64>,
        limit: usize,
    ) -> Result<PendingSignedTransactionPage, WcashTestnetRuntimeError> {
        active_pending_signed_transactions(
            wallet_path,
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

/// A network-attested session for one persistent local Wcash Regtest wallet.
///
/// This runtime is compiled only for QA builds. Transfers use the backend's
/// explicit Regtest policy with one required confirmation.
#[cfg(feature = "regtest")]
#[derive(Debug)]
pub struct WcashRegtestRuntime {
    wallet_path: PathBuf,
    client: AttestedWcashClient,
}

#[cfg(feature = "regtest")]
impl WcashRegtestRuntime {
    /// Creates one new account near the current attested Regtest tip.
    pub async fn create(
        endpoint: &str,
        wallet_path: impl AsRef<Path>,
        master_seed: &SecretVec<u8>,
    ) -> Result<(Self, InitializedWallet), WcashRegtestRuntimeError> {
        Self::initialize(endpoint, wallet_path, master_seed, None).await
    }

    /// Restores one account from an explicit Regtest birthday height.
    pub async fn restore(
        endpoint: &str,
        wallet_path: impl AsRef<Path>,
        master_seed: &SecretVec<u8>,
        birthday_height: u32,
    ) -> Result<(Self, InitializedWallet), WcashRegtestRuntimeError> {
        Self::initialize(endpoint, wallet_path, master_seed, Some(birthday_height)).await
    }

    /// Opens an existing account and attests its Regtest endpoint.
    pub async fn open(
        endpoint: &str,
        wallet_path: impl AsRef<Path>,
    ) -> Result<(Self, WalletInfo), WcashRegtestRuntimeError> {
        let wallet_path = wallet_path.as_ref().to_path_buf();
        let info = Self::inspect(&wallet_path)?;
        let runtime = Self::connect(endpoint, wallet_path).await?;
        Ok((runtime, info))
    }

    /// Reads local account metadata through a read-only database handle.
    pub fn inspect(wallet_path: impl AsRef<Path>) -> Result<WalletInfo, WcashRegtestRuntimeError> {
        inspect_wallet(wallet_path, WcashRegtest.network()).map_err(Into::into)
    }

    /// Returns the database path owned by this runtime.
    pub fn wallet_path(&self) -> &Path {
        &self.wallet_path
    }

    /// Synchronizes through bounded, cancellable, durable backend batches.
    pub async fn sync(
        &mut self,
        cancellation: &WalletSyncCancellation,
    ) -> Result<WalletBalanceSummary, WcashRegtestRuntimeError> {
        synchronize_wallet_cancellable(
            &mut self.client,
            &self.wallet_path,
            WcashRegtest.network(),
            wcash_wallet::MAX_SYNC_BATCH_SIZE,
            cancellation,
        )
        .await
        .map_err(Into::into)
    }

    /// Reads the current fail-closed pool-separated balance.
    pub fn balance(&self) -> Result<WalletBalanceSummary, WcashRegtestRuntimeError> {
        Self::read_balance(&self.wallet_path)
    }

    /// Reads a local wallet balance without opening a network session.
    pub fn read_balance(
        wallet_path: impl AsRef<Path>,
    ) -> Result<WalletBalanceSummary, WcashRegtestRuntimeError> {
        wallet_balance_with_confirmations(
            wallet_path,
            WcashRegtest.network(),
            REGTEST_CONFIRMATIONS,
            ALLOW_UNSAFE_LOCAL_CONFIRMATIONS,
        )
        .map_err(Into::into)
    }

    /// Reads newest-first confirmed transaction metadata at the exact synchronized tip.
    pub fn confirmed_transactions(
        &self,
        limit: usize,
    ) -> Result<ConfirmedTransactionHistory, WcashRegtestRuntimeError> {
        Self::read_confirmed_transactions(&self.wallet_path, limit)
    }

    /// Reads confirmed local transaction metadata without opening a network session.
    pub fn read_confirmed_transactions(
        wallet_path: impl AsRef<Path>,
        limit: usize,
    ) -> Result<ConfirmedTransactionHistory, WcashRegtestRuntimeError> {
        confirmed_transaction_history(wallet_path, WcashRegtest.network(), limit)
            .map_err(Into::into)
    }

    /// Reads confirmed local transaction metadata and wallet-display values.
    pub fn confirmed_transaction_summaries(
        &self,
        limit: usize,
    ) -> Result<ConfirmedTransactionSummaryHistory, WcashRegtestRuntimeError> {
        Self::read_confirmed_transaction_summaries(&self.wallet_path, limit)
    }

    /// Reads confirmed local transaction metadata and values from wallet storage.
    pub fn read_confirmed_transaction_summaries(
        wallet_path: impl AsRef<Path>,
        limit: usize,
    ) -> Result<ConfirmedTransactionSummaryHistory, WcashRegtestRuntimeError> {
        confirmed_transaction_summary_history(wallet_path, WcashRegtest.network(), limit)
            .map_err(Into::into)
    }

    /// Reads the account's canonical local receiving addresses.
    pub fn receive(&self) -> Result<WcashRegtestReceivers, WcashRegtestRuntimeError> {
        Self::inspect(&self.wallet_path).map(Into::into)
    }

    /// Builds, proves, signs, and persists one Ironwood transfer.
    ///
    /// The local policy accepts an input after one confirmation. The returned
    /// bytes remain local until [`Self::broadcast`] is called.
    pub async fn send(
        &mut self,
        master_seed: &SecretVec<u8>,
        payments: Vec<WcashRegtestPayment>,
    ) -> Result<SignedTransaction, WcashRegtestRuntimeError> {
        let recipients = payments.into_iter().map(Into::into).collect();
        create_signed_transfer(
            &mut self.client,
            &self.wallet_path,
            WcashRegtest.network(),
            master_seed,
            recipients,
            REGTEST_CONFIRMATIONS,
            ALLOW_UNSAFE_LOCAL_CONFIRMATIONS,
            DEFAULT_EXPIRY_DELTA,
            DEFAULT_LOCK_FOR_BLOCKS,
        )
        .await
        .map_err(Into::into)
    }

    /// Selects and locks one Ironwood transfer using public wallet state.
    pub fn propose_send(
        wallet_path: impl AsRef<Path>,
        payments: Vec<WcashRegtestPayment>,
    ) -> Result<StagedTransactionProposal, WcashRegtestRuntimeError> {
        propose_transfer_offline(
            wallet_path,
            WcashRegtest.network(),
            payments.into_iter().map(Into::into).collect(),
            REGTEST_CONFIRMATIONS,
            ALLOW_UNSAFE_LOCAL_CONFIRMATIONS,
            DEFAULT_EXPIRY_DELTA,
            DEFAULT_LOCK_FOR_BLOCKS,
        )
        .map_err(Into::into)
    }

    /// Selects and locks mature transparent coinbase outputs.
    pub fn propose_shield_coinbase(
        wallet_path: impl AsRef<Path>,
    ) -> Result<StagedTransactionProposal, WcashRegtestRuntimeError> {
        propose_coinbase_shielding_offline(
            wallet_path,
            WcashRegtest.network(),
            DEFAULT_COINBASE_INPUTS,
            DEFAULT_EXPIRY_DELTA,
            DEFAULT_LOCK_FOR_BLOCKS,
        )
        .map_err(Into::into)
    }

    /// Signs the exact staged proposal using the local wallet state.
    pub fn calculate(
        wallet_path: impl AsRef<Path>,
        master_seed: &SecretVec<u8>,
        staged: &StagedTransactionProposal,
    ) -> Result<CalculatedTransaction, WcashRegtestRuntimeError> {
        calculate_staged_transaction(wallet_path, WcashRegtest.network(), master_seed, staged)
            .map_err(Into::into)
    }

    /// Releases the input locks held by an abandoned Regtest proposal.
    pub fn cancel(
        wallet_path: impl AsRef<Path>,
        staged: &StagedTransactionProposal,
    ) -> Result<(), WcashRegtestRuntimeError> {
        cancel_staged_transaction(wallet_path, WcashRegtest.network(), staged).map_err(Into::into)
    }

    /// Shields mature transparent coinbase outputs into Ironwood.
    pub async fn shield_coinbase(
        &mut self,
        master_seed: &SecretVec<u8>,
    ) -> Result<SignedTransaction, WcashRegtestRuntimeError> {
        create_signed_coinbase_shielding(
            &mut self.client,
            &self.wallet_path,
            WcashRegtest.network(),
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
    ) -> Result<BroadcastResult, WcashRegtestRuntimeError> {
        let raw = validate_regtest_signed_bytes(
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

    /// Revalidates and broadcasts the exact transaction returned by [`Self::calculate`].
    pub async fn broadcast_calculated(
        &mut self,
        calculated: &CalculatedTransaction,
    ) -> Result<BroadcastResult, WcashRegtestRuntimeError> {
        broadcast_calculated_transaction(&mut self.client, calculated)
            .await
            .map_err(Into::into)
    }

    /// Lists signed bytes that can be recovered after an interrupted app call.
    pub fn pending_transactions(
        &self,
        after_row_id: Option<u64>,
        limit: usize,
    ) -> Result<PendingSignedTransactionPage, WcashRegtestRuntimeError> {
        pending_signed_transactions(
            &self.wallet_path,
            WcashRegtest.network(),
            after_row_id,
            limit,
        )
        .map_err(Into::into)
    }

    /// Lists transactions valid at the exact wallet tip.
    pub fn active_pending_transactions(
        &self,
        expected_tip: Option<BlockRef>,
        after_row_id: Option<u64>,
        limit: usize,
    ) -> Result<PendingSignedTransactionPage, WcashRegtestRuntimeError> {
        active_pending_signed_transactions(
            &self.wallet_path,
            WcashRegtest.network(),
            expected_tip,
            after_row_id,
            limit,
        )
        .map_err(Into::into)
    }

    /// Lists transactions valid at the exact wallet tip through a read-only local session.
    pub fn read_active_pending_transactions(
        wallet_path: impl AsRef<Path>,
        expected_tip: Option<BlockRef>,
        after_row_id: Option<u64>,
        limit: usize,
    ) -> Result<PendingSignedTransactionPage, WcashRegtestRuntimeError> {
        active_pending_signed_transactions(
            wallet_path,
            WcashRegtest.network(),
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
    ) -> Result<BroadcastResult, WcashRegtestRuntimeError> {
        let raw = validate_regtest_signed_bytes(
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
    ) -> Result<(Self, InitializedWallet), WcashRegtestRuntimeError> {
        let wallet_path = wallet_path.as_ref().to_path_buf();
        let mut runtime = Self::connect(endpoint, wallet_path).await?;
        let initialized = initialize_wallet(
            &mut runtime.client,
            &runtime.wallet_path,
            WcashRegtest.network(),
            master_seed,
            birthday_height,
        )
        .await?;
        if initialized.created {
            Ok((runtime, initialized))
        } else {
            Err(WcashRegtestRuntimeError::WalletAlreadyInitialized)
        }
    }

    async fn connect(
        endpoint: &str,
        wallet_path: PathBuf,
    ) -> Result<Self, WcashRegtestRuntimeError> {
        let client = AttestedWcashClient::connect(endpoint, WcashRegtest.network()).await?;
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

#[cfg(feature = "regtest")]
fn validate_regtest_signed_bytes(
    expected_txid: &str,
    branch_id: &str,
    expiry_height: u32,
    raw_transaction_hex: &str,
) -> Result<Vec<u8>, WcashRegtestRuntimeError> {
    if branch_id != WcashRegtest.network().branch_id_hex() {
        return Err(WcashRegtestRuntimeError::SignedTransactionMetadataMismatch);
    }
    let raw = hex::decode(raw_transaction_hex)
        .map_err(WcashRegtestRuntimeError::InvalidSignedTransactionHex)?;
    let transaction = inspect_signed_transaction(&raw, WcashRegtest.network())?;
    let actual_expiry_height = u32::from(transaction.expiry_height());
    if transaction.txid().to_string() != expected_txid || actual_expiry_height != expiry_height {
        return Err(WcashRegtestRuntimeError::SignedTransactionMetadataMismatch);
    }
    Ok(raw)
}

#[cfg(test)]
mod tests {
    use zcash_protocol::consensus::BranchId;

    use super::*;

    const WCASH_TESTNET_BRANCH_ID: u32 = 0xb3cf_d27e;
    #[cfg(feature = "regtest")]
    const WCASH_REGTEST_BRANCH_ID: u32 = 0xc3a6_678a;
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
    const FIXED_TESTNET_RECIPIENT: &str = "wutest17mvne4ygv9v8rkjf6yxnrveceejh8nutee8svp8swkgj7s7ac9ga36u2av8hgpc28cc42u474ypjq2jsdt64utcxtztm2jr6guvaryhh";
    #[cfg(feature = "regtest")]
    const FIXED_REGTEST_RECIPIENT: &str = "wuregtest1xryxj7ddyajw4mv7jpelftnfhkwu3v5w03smp88kk6fkmfvlewpzrs26pxqs4wycul43485lg0h9ry8zzxkj9q8gvh7dmg0uh5e2t28k";

    #[test]
    fn profile_matches_the_frozen_wcash_testnet_identity() {
        let profile = WcashTestnet;

        assert_eq!(profile.network(), WalletNetwork::Testnet);
        assert_eq!(profile.ticker(), WCASH_TESTNET_TICKER);
        assert_eq!(profile.network_label(), WCASH_TESTNET_NETWORK_LABEL);
        assert_eq!(
            profile.genesis_hash_display(),
            WCASH_TESTNET_GENESIS_DISPLAY
        );
        assert_eq!(profile.branch_id(), WCASH_TESTNET_BRANCH_ID);
        assert_eq!(profile.storage_namespace(), WCASH_TESTNET_STORAGE_NAMESPACE);
        assert_eq!(profile.default_endpoint(), PUBLIC_TESTNET_ENDPOINT);
        assert_eq!(profile.required_confirmations(), PUBLIC_CONFIRMATIONS);
        profile.validate_recipient(FIXED_TESTNET_RECIPIENT).unwrap();
    }

    #[cfg(feature = "regtest")]
    #[test]
    fn profile_matches_the_frozen_wcash_regtest_identity() {
        let profile = WcashRegtest;
        let mut genesis_hash_display = profile.genesis_hash();
        genesis_hash_display.reverse();

        assert_eq!(profile.network(), WalletNetwork::Regtest);
        assert_eq!(profile.ticker(), WCASH_REGTEST_TICKER);
        assert_eq!(profile.network_label(), WCASH_REGTEST_NETWORK_LABEL);
        assert_eq!(
            hex::encode(genesis_hash_display),
            WCASH_REGTEST_GENESIS_DISPLAY
        );
        assert_eq!(
            profile.genesis_hash_display(),
            WCASH_REGTEST_GENESIS_DISPLAY
        );
        assert_eq!(profile.branch_id(), WCASH_REGTEST_BRANCH_ID);
        assert_eq!(profile.storage_namespace(), WCASH_REGTEST_STORAGE_NAMESPACE);
        assert_eq!(profile.required_confirmations(), REGTEST_CONFIRMATIONS);
        profile.validate_recipient(FIXED_REGTEST_RECIPIENT).unwrap();
    }

    #[cfg(feature = "regtest")]
    #[test]
    fn regtest_identity_is_disjoint_from_testnet() {
        assert_ne!(WcashRegtest.network(), WcashTestnet.network());
        assert_ne!(WcashRegtest.genesis_hash(), WcashTestnet.genesis_hash());
        assert_ne!(WcashRegtest.branch_id(), WcashTestnet.branch_id());
        assert_ne!(
            WcashRegtest.storage_namespace(),
            WcashTestnet.storage_namespace()
        );
        assert!(
            WcashTestnet
                .validate_recipient(FIXED_REGTEST_RECIPIENT)
                .is_err()
        );
        assert!(
            WcashRegtest
                .validate_recipient(FIXED_TESTNET_RECIPIENT)
                .is_err()
        );
    }

    #[cfg(feature = "regtest")]
    #[test]
    fn signed_metadata_cannot_cross_wcash_networks() {
        const UNUSED_TXID: &str = "unexamined";
        const UNUSED_EXPIRY_HEIGHT: u32 = 0;
        const UNUSED_RAW_TRANSACTION: &str = "00";

        let error = validate_regtest_signed_bytes(
            UNUSED_TXID,
            &WcashTestnet.network().branch_id_hex(),
            UNUSED_EXPIRY_HEIGHT,
            UNUSED_RAW_TRANSACTION,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            WcashRegtestRuntimeError::SignedTransactionMetadataMismatch
        ));
    }

    #[cfg(feature = "regtest")]
    #[test]
    fn wallet_database_identity_cannot_cross_wcash_networks() {
        let directory = tempfile::tempdir().unwrap();
        let wallet_path = directory.path().join("wallet.db");
        drop(wcash_wallet::open_wallet_database(&wallet_path, WcashRegtest.network()).unwrap());

        let error = WcashTestnetRuntime::inspect(&wallet_path).unwrap_err();

        assert!(matches!(
            error,
            WcashTestnetRuntimeError::Wallet(WalletServiceError::ForeignWalletDatabase)
        ));
        assert!(matches!(
            WcashTestnetRuntime::read_balance(&wallet_path),
            Err(WcashTestnetRuntimeError::Wallet(
                WalletServiceError::ForeignWalletDatabase
            ))
        ));
        assert!(matches!(
            WcashTestnetRuntime::read_confirmed_transactions(
                &wallet_path,
                MAX_CONFIRMED_TRANSACTION_HISTORY_SIZE
            ),
            Err(WcashTestnetRuntimeError::Wallet(
                WalletServiceError::ForeignWalletDatabase
            ))
        ));
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
        let history = runtime
            .confirmed_transactions(MAX_CONFIRMED_TRANSACTION_HISTORY_SIZE)
            .unwrap();
        assert_eq!(history.exact_tip.height, synchronized.chain_tip_height);
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
