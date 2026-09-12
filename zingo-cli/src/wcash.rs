//! Wcash session routing for the upstream Zingo command surface.

use std::collections::HashSet;
use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::mpsc::channel;

use bip0039::{Count, English, Mnemonic};
use secrecy::{ExposeSecret, SecretString, SecretVec};
use sha2::{Digest, Sha256};
use zcash_protocol::PoolType;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::memo::MemoBytes;
use zcash_protocol::value::Zatoshis;
use zingo_status::confirmation_status::ConfirmationStatus;
use zingolib::config::ChainType;
use zingolib::utils::conversion::txid_from_hex_encoded_str;
use zingolib::wallet::balance::AccountBalance;
use zingolib::wallet::summary::data::{
    SendType, TransactionKind, TransactionSummaries, TransactionSummary,
};
#[cfg(test)]
use zingolib::wcash::StoredSignedTransaction;
use zingolib::wcash::{
    BroadcastResult, CalculatedTransaction, ConfirmedTransactionDirection,
    ConfirmedTransactionKind, ConfirmedTransactionSummaryHistory, InitializedWallet,
    MAX_CONFIRMED_TRANSACTION_HISTORY_SIZE, MAX_PENDING_TRANSACTION_PAGE_SIZE,
    PendingSignedTransactionPage, StagedTransactionProposal, WalletBalanceSummary, WalletInfo,
    WalletSyncCancellation, WcashRegtest, WcashRegtestRuntime, WcashTestnet, WcashTestnetPayment,
    WcashTestnetRuntime,
};

use crate::commands::{CliCommand, RT, SaveSubCommand, SyncSubCommand};
use crate::{
    CliConfigTemplate, CommandChannel, Communications, Operations, Request, offline_mode_refusal,
    start_interactive, start_noninteractive,
};

const WALLET_FILE_EXTENSION: &str = "sqlite3";
const ACCOUNT_INDEX: u32 = u32::MIN;
const ADDRESS_INDEX: u32 = u32::MIN;
const UNKNOWN_TIMESTAMP: u32 = u32::MIN;
const NO_POOL_VALUE: u64 = u64::MIN;
const ZERO_VALUE_LINE: &str = "    value: 0\n";
const UNKNOWN_VALUE_LINE: &str = "    value: not available\n";
const ONE_REPLACEMENT: usize = 1;
const NO_SCANNED_LEGACY_OUTPUTS: u32 = u32::MIN;
const COMPLETE_PERCENTAGE: u32 = 100;
const FIRST_CHAIN_HEIGHT: u32 = 1;
const COMMAND_NAME_COUNT: usize = 1;
const JSON_INDENT: u16 = 2;
const WALLET_KIND_JSON_INDENT: u16 = 4;
const CREDENTIAL_SERVICE: &str = "org.wcash.wallet.cli";
const CREDENTIAL_SCHEMA: &[u8] = b"wcash-cli-mnemonic-v1";
#[cfg(target_os = "macos")]
const CREDENTIAL_STORE_DESCRIPTION: &str = "macOS Keychain Services";
#[cfg(target_os = "windows")]
const CREDENTIAL_STORE_DESCRIPTION: &str = "Windows Credential Manager";
#[cfg(target_os = "linux")]
const CREDENTIAL_STORE_DESCRIPTION: &str =
    "Linux Secret Service over the logged-in desktop D-Bus session";
#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
const CREDENTIAL_STORE_DESCRIPTION: &str = "platform credential service";
const WALLET_ACCOUNT_COUNT: u32 = 1;
const SUPPORTED_COMMAND_NAMES: &[&str] = &[
    "addresses",
    "balance",
    "birthday",
    "calculate",
    "confirm",
    "height",
    "help",
    "quit",
    "recovery_info",
    "save",
    "send",
    "shield",
    "sync",
    "t_addresses",
    "transactions",
    "version",
    "wallet_kind",
];

/// Builds the Wcash command tree from the supported upstream definitions.
pub(super) fn augment_commands(mut session: clap::Command) -> clap::Command {
    use clap::Subcommand as _;

    session = session
        .mut_arg("chain", |arg| {
            arg.help(
                "Wcash network. Use testnet or regtest. The default is testnet. Mainnet is disabled until its consensus identity is frozen.",
            )
        })
        .mut_arg("seed", |arg| {
            arg.help(
                "Restore signing access from a 24-word phrase. The phrase is saved in the platform credential store after wallet authority is verified. A phrase passed here is visible in this host's process list and shell history. Export WCASH_SEED instead to keep it to this process and its child.",
            )
        })
        .mut_arg("birthday", |arg| {
            arg.help("Earliest Wcash block height to scan when restoring a wallet")
        })
        .mut_arg("nosync", |arg| {
            arg.help("Skip automatic synchronization for an online Wcash session")
        })
        .mut_arg("waitsync", |arg| arg.hide(true))
        .mut_arg("offline", |arg| {
            arg.help("Keep this session offline. Local reads and transaction proposals remain available.")
        })
        .mut_arg("online", |arg| {
            arg.help("Connect this session to the fixed endpoint for the selected Wcash network.")
        })
        .mut_arg("server", |arg| arg.hide(true))
        .mut_arg("viewkey", |arg| arg.hide(true))
        .mut_arg("nym-proxy", |arg| arg.hide(true));
    let source = CliCommand::augment_subcommands(clap::Command::new("wcash-commands"));
    let commands = source
        .get_subcommands()
        .filter(|command| SUPPORTED_COMMAND_NAMES.contains(&command.get_name()))
        .cloned()
        .map(sanitize_command)
        .collect::<Vec<_>>();
    session.subcommands(commands)
}

fn sanitize_command(mut command: clap::Command) -> clap::Command {
    command = match command.get_name() {
        "send" => command
            .about("Propose a Wcash transfer and print its fee")
            .long_about(
                "Propose a Wcash transfer and print its fee. Run `calculate` to sign the current proposal, then `confirm` to broadcast those exact bytes.",
            ),
        "calculate" => command
            .about("Sign the current Wcash proposal offline")
            .long_about(
                "Sign the current Wcash proposal from local wallet state. The confirm command handles network access and broadcast.",
            ),
        "confirm" => command
            .about("Broadcast the current calculated Wcash transaction")
            .long_about(
                "Revalidate the current calculated Wcash transaction against its canonical chain anchors, then broadcast its exact bytes.",
            ),
        "shield" => command
            .about("Propose shielding mature transparent coinbase funds")
            .long_about(
                "Propose moving mature transparent coinbase funds into Ironwood. Run `calculate`, then `confirm`.",
            ),
        "save" => {
            let subs = command
                .get_subcommands()
                .cloned()
                .map(|subcommand| match subcommand.get_name() {
                    "run" => subcommand.about("Confirm that SQLite persistence is active"),
                    "check" => subcommand.about("Check SQLite persistence state"),
                    "shutdown" => subcommand.about("Report that no save task is running"),
                    _ => subcommand,
                })
                .collect::<Vec<_>>();
            clap::Command::new("save")
                .about("Inspect the SQLite persistence state")
                .long_about("Wcash wallet state is committed to SQLite during each operation.")
                .subcommands(subs)
        }
        "wallet_kind" => command.long_about(
            "Print whether the platform credential store contains spending authority for this Wcash wallet.",
        ),
        "height" => command
            .about("Print the Wcash chain height stored by the wallet")
            .long_about("Print the exact Wcash chain tip stored by the latest completed sync."),
        "birthday" => command
            .about("Print the earliest Wcash block height selected for this wallet")
            .long_about("Print the wallet birthday used as the lower bound for chain scanning."),
        "transactions" => command
            .about("List confirmed and active pending Wcash transactions")
            .long_about(
                "List confirmed history and active locally signed transactions at the attested wallet tip.",
            ),
        "quit" => command
            .about("Quit Wcash Wallet")
            .long_about("Quit the current Wcash Wallet session."),
        "sync" => {
            let run = command
                .get_subcommands()
                .find(|subcommand| subcommand.get_name() == "run")
                .cloned()
                .map(|run| run.about("Run Wcash synchronization to completion"));
            let sync = clap::Command::new("sync")
                .about("Sync the wallet to the Wcash chain tip")
                .long_about("Run the Wcash synchronization task to completion.");
            if let Some(run) = run {
                sync.subcommand(run)
            } else {
                sync
            }
        }
        _ => command,
    };
    brand_clap_command(command)
}

fn brand_clap_command(mut command: clap::Command) -> clap::Command {
    if let Some(about) = command.get_about().map(ToString::to_string) {
        command = command.about(brand_help(about));
    }
    if let Some(long_about) = command.get_long_about().map(ToString::to_string) {
        command = command.long_about(brand_help(long_about));
    }
    let subcommand_names = command
        .get_subcommands()
        .map(|subcommand| subcommand.get_name().to_string())
        .collect::<Vec<_>>();
    for name in subcommand_names {
        command = command.mut_subcommand(name, brand_clap_command);
    }
    command
}

/// Rebrands visible upstream help prose while retaining command and argument names.
pub(super) fn brand_help(help: String) -> String {
    help.replace("ZingoLabs", "Wcash Wallet")
        .replace("zingolabs", "Wcash Wallet")
        .replace("Zingo CLI", "Wcash Wallet")
        .replace("Zcash", "Wcash")
        .replace("ZEC", "Wcash")
}

/// Renders help from the supported Wcash command tree.
pub(super) fn format_help(command: Option<&str>) -> String {
    let mut model = crate::build_clap_app();
    let Some(name) = command else {
        return model.render_long_help().to_string();
    };
    match model.find_subcommand_mut(name) {
        Some(subcommand) => subcommand.render_long_help().to_string(),
        None => format!("Command {name} not found"),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WcashChain {
    Testnet,
    Regtest,
}

impl WcashChain {
    fn from_chain_type(chain_type: &ChainType) -> Result<Self, String> {
        match chain_type {
            ChainType::Testnet => Ok(Self::Testnet),
            ChainType::Regtest(_) => Ok(Self::Regtest),
            ChainType::Mainnet => Err(
                "Wcash Mainnet is unavailable until its consensus identity is frozen".to_string(),
            ),
        }
    }

    fn storage_namespace(self) -> &'static str {
        match self {
            Self::Testnet => WcashTestnet.storage_namespace(),
            Self::Regtest => WcashRegtest.storage_namespace(),
        }
    }

    fn wallet_path(self, data_dir: &Path) -> PathBuf {
        data_dir.join(format!(
            "{}.{}",
            self.storage_namespace(),
            WALLET_FILE_EXTENSION
        ))
    }

    fn endpoint(self, cli_config: &CliConfigTemplate) -> Result<Option<String>, String> {
        if cli_config.communications != Communications::Online {
            return Ok(None);
        }
        match self {
            Self::Testnet => Ok(Some(WcashTestnet.default_endpoint().to_string())),
            Self::Regtest => Ok(Some(WcashRegtest.default_endpoint().to_string())),
        }
    }

    fn inspect(self, wallet_path: &Path) -> Result<WalletInfo, String> {
        match self {
            Self::Testnet => WcashTestnetRuntime::inspect(wallet_path),
            Self::Regtest => WcashRegtestRuntime::inspect(wallet_path),
        }
        .map_err(|error| error.to_string())
    }

    fn balance(self, wallet_path: &Path) -> Result<WalletBalanceSummary, String> {
        match self {
            Self::Testnet => WcashTestnetRuntime::read_balance(wallet_path),
            Self::Regtest => WcashRegtestRuntime::read_balance(wallet_path),
        }
        .map_err(|error| error.to_string())
    }

    fn confirmed_transactions(
        self,
        wallet_path: &Path,
    ) -> Result<ConfirmedTransactionSummaryHistory, String> {
        match self {
            Self::Testnet => WcashTestnetRuntime::read_confirmed_transaction_summaries(
                wallet_path,
                MAX_CONFIRMED_TRANSACTION_HISTORY_SIZE,
            ),
            Self::Regtest => WcashRegtestRuntime::read_confirmed_transaction_summaries(
                wallet_path,
                MAX_CONFIRMED_TRANSACTION_HISTORY_SIZE,
            ),
        }
        .map_err(|error| error.to_string())
    }

    fn active_pending_transactions(
        self,
        wallet_path: &Path,
    ) -> Result<PendingSignedTransactionPage, String> {
        match self {
            Self::Testnet => WcashTestnetRuntime::read_active_pending_transactions(
                wallet_path,
                None,
                None,
                MAX_PENDING_TRANSACTION_PAGE_SIZE,
            ),
            Self::Regtest => WcashRegtestRuntime::read_active_pending_transactions(
                wallet_path,
                None,
                None,
                MAX_PENDING_TRANSACTION_PAGE_SIZE,
            ),
        }
        .map_err(|error| error.to_string())
    }

    fn validate_recipient(self, address: &str) -> Result<(), String> {
        match self {
            Self::Testnet => WcashTestnet.validate_recipient(address),
            Self::Regtest => WcashRegtest.validate_recipient(address),
        }
        .map_err(|error| error.to_string())
    }

    fn verify_seed(self, wallet_path: &Path, master_seed: &SecretVec<u8>) -> Result<(), String> {
        match self {
            Self::Testnet => WcashTestnet.verify_seed(wallet_path, master_seed),
            Self::Regtest => WcashRegtest.verify_seed(wallet_path, master_seed),
        }
        .map_err(|error| error.to_string())
    }

    fn propose_send(
        self,
        wallet_path: &Path,
        payments: Vec<WcashTestnetPayment>,
    ) -> Result<StagedTransactionProposal, String> {
        match self {
            Self::Testnet => WcashTestnetRuntime::propose_send(wallet_path, payments),
            Self::Regtest => WcashRegtestRuntime::propose_send(wallet_path, payments),
        }
        .map_err(|error| error.to_string())
    }

    fn propose_shield(self, wallet_path: &Path) -> Result<StagedTransactionProposal, String> {
        match self {
            Self::Testnet => WcashTestnetRuntime::propose_shield_coinbase(wallet_path),
            Self::Regtest => WcashRegtestRuntime::propose_shield_coinbase(wallet_path),
        }
        .map_err(|error| error.to_string())
    }

    fn calculate(
        self,
        wallet_path: &Path,
        master_seed: &SecretVec<u8>,
        staged: &StagedTransactionProposal,
    ) -> Result<CalculatedTransaction, String> {
        match self {
            Self::Testnet => WcashTestnetRuntime::calculate(wallet_path, master_seed, staged),
            Self::Regtest => WcashRegtestRuntime::calculate(wallet_path, master_seed, staged),
        }
        .map_err(|error| error.to_string())
    }

    fn cancel(self, wallet_path: &Path, staged: &StagedTransactionProposal) -> Result<(), String> {
        match self {
            Self::Testnet => WcashTestnetRuntime::cancel(wallet_path, staged),
            Self::Regtest => WcashRegtestRuntime::cancel(wallet_path, staged),
        }
        .map_err(|error| error.to_string())
    }
}

#[derive(Debug)]
enum OnlineRuntime {
    Testnet(WcashTestnetRuntime),
    Regtest(WcashRegtestRuntime),
}

impl OnlineRuntime {
    async fn sync(&mut self) -> Result<WalletBalanceSummary, String> {
        let cancellation = WalletSyncCancellation::new();
        match self {
            Self::Testnet(runtime) => runtime.sync(&cancellation).await,
            Self::Regtest(runtime) => runtime.sync(&cancellation).await,
        }
        .map_err(|error| error.to_string())
    }

    async fn broadcast_calculated(
        &mut self,
        calculated: &CalculatedTransaction,
    ) -> Result<BroadcastResult, String> {
        match self {
            Self::Testnet(runtime) => runtime.broadcast_calculated(calculated).await,
            Self::Regtest(runtime) => runtime.broadcast_calculated(calculated).await,
        }
        .map_err(|error| error.to_string())
    }
}

struct CredentialStore {
    account: String,
    #[cfg(test)]
    test_phrase: Option<SecretString>,
}

impl CredentialStore {
    fn for_wallet(chain: WcashChain, wallet_path: &Path) -> Self {
        let mut hash = Sha256::new();
        hash.update(CREDENTIAL_SCHEMA);
        hash.update(chain.storage_namespace().as_bytes());
        hash.update(wallet_path.as_os_str().as_encoded_bytes());
        Self {
            account: hex::encode(hash.finalize()),
            #[cfg(test)]
            test_phrase: None,
        }
    }

    #[cfg(test)]
    fn for_test(phrase: &str) -> Self {
        Self {
            account: "test-wallet".to_string(),
            test_phrase: Some(SecretString::new(phrase.to_string())),
        }
    }

    fn store(&mut self, phrase: &str) -> Result<(), String> {
        #[cfg(test)]
        if self.test_phrase.is_some() {
            self.test_phrase = Some(SecretString::new(phrase.to_string()));
            return Ok(());
        }
        self.entry()?.set_password(phrase).map_err(credential_error)
    }

    fn load(&self) -> Result<Option<SecretString>, String> {
        #[cfg(test)]
        if let Some(phrase) = &self.test_phrase {
            return Ok(Some(phrase.clone()));
        }
        match self.entry()?.get_password() {
            Ok(phrase) => Ok(Some(SecretString::new(phrase))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(credential_error(error)),
        }
    }

    fn remove(&self) -> Result<(), String> {
        match self.entry()?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(credential_error(error)),
        }
    }

    fn entry(&self) -> Result<keyring::Entry, String> {
        keyring::Entry::new(CREDENTIAL_SERVICE, &self.account).map_err(credential_error)
    }
}

fn credential_error(error: keyring::Error) -> String {
    format!("{CREDENTIAL_STORE_DESCRIPTION} rejected the Wcash recovery phrase: {error}")
}

struct WcashCliSession {
    chain: WcashChain,
    wallet_path: PathBuf,
    runtime: Option<OnlineRuntime>,
    credentials: CredentialStore,
    proposal: Option<StagedTransactionProposal>,
    calculated: Option<CalculatedTransaction>,
    transmitted_txids: HashSet<String>,
    info: WalletInfo,
    last_sync: Option<String>,
}

impl WcashCliSession {
    fn balance(&self) -> Result<WalletBalanceSummary, String> {
        self.chain.balance(&self.wallet_path)
    }

    fn sync(&mut self) -> Result<String, String> {
        let start_height = self.balance().map_or_else(
            |_| self.info.birthday_height.saturating_sub(FIRST_CHAIN_HEIGHT),
            |summary| summary.fully_scanned_height,
        );
        let runtime = self
            .runtime
            .as_mut()
            .ok_or_else(|| "sync requires an online Wcash session".to_string())?;
        let summary = RT.block_on(runtime.sync())?;
        Ok(render_sync(start_height, &summary))
    }

    fn prompt_indicator(&self) -> String {
        self.balance().map_or_else(
            |_| "Block:0 [Sync stopped]".to_string(),
            |summary| {
                let state = if summary.synchronized {
                    "Synced"
                } else {
                    "Sync stopped"
                };
                format!("Block:{} [{state}]", summary.fully_scanned_height)
            },
        )
    }
}

/// Resolves the Wcash session connectivity posture.
pub(super) fn communications(matches: &clap::ArgMatches) -> io::Result<Communications> {
    let data_dir = super::data_dir_from(matches);
    if matches.get_flag("forget-online") {
        zingolib::connectivity::forget_connectivity_consent(&data_dir)?;
        eprintln!("Standing Connectivity Consent forgotten. Future sessions start offline again.");
    }

    let explicit_server =
        matches.value_source("server") == Some(clap::parser::ValueSource::CommandLine);
    if explicit_server {
        return Err(io::Error::other(
            "Wcash network endpoints are fixed by the selected chain profile",
        ));
    }
    if matches.get_flag("offline") {
        eprintln!("{}", super::DELIBERATE_OFFLINE_NOTICE);
        return Ok(Communications::DeliberateOffline);
    }

    let stored_online = matches!(
        zingolib::connectivity::load_connectivity_consent(&data_dir),
        zingolib::connectivity::ConnectivityConsent::StandingOnline
    );
    let remember_online = matches.get_flag("remember-online");
    if remember_online {
        zingolib::connectivity::store_standing_online(&data_dir)?;
        eprintln!(
            "Standing Connectivity Consent stored in '{}'. Future sessions attach to the network automatically. Undo with --forget-online.",
            data_dir
                .join(zingolib::connectivity::CONNECTIVITY_CONSENT_FILE)
                .display()
        );
    }

    if matches.get_flag("online") || remember_online || stored_online {
        Ok(Communications::Online)
    } else {
        eprintln!(
            "No Connectivity Consent is recorded, so this Wcash Wallet session runs offline. Pass --online or --remember-online to connect."
        );
        Ok(Communications::UnconsentedOffline)
    }
}

/// Returns the connectivity posture used to render pre-startup help.
pub(super) fn posture_preview(matches: &clap::ArgMatches) -> Communications {
    if matches.get_flag("offline") {
        return Communications::DeliberateOffline;
    }
    let stored_online = matches!(
        zingolib::connectivity::load_connectivity_consent(&super::data_dir_from(matches)),
        zingolib::connectivity::ConnectivityConsent::StandingOnline
    );
    if matches.get_flag("online") || matches.get_flag("remember-online") || stored_online {
        Communications::Online
    } else {
        Communications::UnconsentedOffline
    }
}

/// Starts the Wcash wallet and enters the existing one-shot or interactive frontend.
pub(super) fn dispatch_command_or_start_interactive(
    cli_config: &CliConfigTemplate,
) -> io::Result<ExitCode> {
    let session = startup(cli_config).map_err(io::Error::other)?;
    let ch = command_loop(session, cli_config.communications);
    match &cli_config.mode {
        Operations::Interactive => Ok(start_interactive(cli_config, ch)),
        Operations::NonInteractive { command } => Ok(start_noninteractive(command, ch)),
    }
}

fn startup(cli_config: &CliConfigTemplate) -> Result<WcashCliSession, String> {
    let chain = WcashChain::from_chain_type(&cli_config.chaintype)?;
    std::fs::create_dir_all(&cli_config.data_dir).map_err(|error| error.to_string())?;
    let wallet_path = chain.wallet_path(&cli_config.data_dir);
    let endpoint = chain.endpoint(cli_config)?;
    let mut credentials = CredentialStore::for_wallet(chain, &wallet_path);

    if cli_config.ufvk.is_some() {
        return Err("Wcash viewing-key restore is not available in this release".to_string());
    }
    if cli_config.server.is_some() {
        return Err("Wcash network endpoints are fixed by the selected chain profile".to_string());
    }
    if cli_config.nym_proxy_path.is_some() {
        return Err("Wcash does not accept a Zingo nym-proxy override".to_string());
    }

    let (runtime, info) = if wallet_path.exists() {
        let info = chain.inspect(&wallet_path)?;
        if let Some(phrase) = cli_config.seed.as_deref() {
            let master_seed = master_seed_from_phrase(phrase)?;
            chain.verify_seed(&wallet_path, &master_seed)?;
            credentials.store(phrase)?;
        }
        let runtime = endpoint
            .as_deref()
            .map(|endpoint| RT.block_on(open_runtime(chain, endpoint, &wallet_path)))
            .transpose()?;
        (runtime, info)
    } else {
        let endpoint = endpoint
            .as_deref()
            .ok_or_else(|| "creating a Wcash wallet requires an online session".to_string())?;
        let supplied = cli_config.seed.as_deref();
        let mnemonic = supplied.map_or_else(
            || Ok(Mnemonic::<English>::generate(Count::Words24)),
            |phrase| Mnemonic::<English>::from_phrase(phrase).map_err(|error| error.to_string()),
        )?;
        let phrase = mnemonic.phrase();
        let master_seed = SecretVec::new(mnemonic.to_seed("").as_slice().to_vec());
        let birthday = u32::try_from(cli_config.birthday)
            .map_err(|_| "the Wcash wallet birthday exceeds u32".to_string())?;
        credentials.store(phrase)?;
        let initialized = RT.block_on(initialize_runtime(
            chain,
            endpoint,
            &wallet_path,
            &master_seed,
            supplied.is_some().then_some(birthday),
        ));
        let (runtime, initialized) = match initialized {
            Ok(initialized) => initialized,
            Err(error) => {
                let _ = credentials.remove();
                return Err(error);
            }
        };
        if supplied.is_none() {
            println!("Wcash Wallet recovery phrase:\n{phrase}");
        }
        (Some(runtime), wallet_info(initialized))
    };

    let mut session = WcashCliSession {
        chain,
        wallet_path,
        runtime,
        credentials,
        proposal: None,
        calculated: None,
        transmitted_txids: HashSet::new(),
        info,
        last_sync: None,
    };
    let command_is_sync = matches!(
        &cli_config.mode,
        Operations::NonInteractive {
            command: CliCommand::Sync {
                sub: SyncSubCommand::Run
            }
        }
    );
    if cli_config.sync && !command_is_sync {
        session.sync()?;
    }
    Ok(session)
}

fn master_seed_from_phrase(phrase: &str) -> Result<SecretVec<u8>, String> {
    Mnemonic::<English>::from_phrase(phrase)
        .map(|mnemonic| SecretVec::new(mnemonic.to_seed("").as_slice().to_vec()))
        .map_err(|error| error.to_string())
}

async fn open_runtime(
    chain: WcashChain,
    endpoint: &str,
    wallet_path: &Path,
) -> Result<OnlineRuntime, String> {
    match chain {
        WcashChain::Testnet => WcashTestnetRuntime::open(endpoint, wallet_path)
            .await
            .map(|(runtime, _)| OnlineRuntime::Testnet(runtime)),
        WcashChain::Regtest => WcashRegtestRuntime::open(endpoint, wallet_path)
            .await
            .map(|(runtime, _)| OnlineRuntime::Regtest(runtime)),
    }
    .map_err(|error| error.to_string())
}

async fn initialize_runtime(
    chain: WcashChain,
    endpoint: &str,
    wallet_path: &Path,
    master_seed: &SecretVec<u8>,
    birthday: Option<u32>,
) -> Result<(OnlineRuntime, InitializedWallet), String> {
    match (chain, birthday) {
        (WcashChain::Testnet, Some(birthday)) => {
            WcashTestnetRuntime::restore(endpoint, wallet_path, master_seed, birthday)
                .await
                .map(|(runtime, initialized)| (OnlineRuntime::Testnet(runtime), initialized))
        }
        (WcashChain::Testnet, None) => {
            WcashTestnetRuntime::create(endpoint, wallet_path, master_seed)
                .await
                .map(|(runtime, initialized)| (OnlineRuntime::Testnet(runtime), initialized))
        }
        (WcashChain::Regtest, Some(birthday)) => {
            WcashRegtestRuntime::restore(endpoint, wallet_path, master_seed, birthday)
                .await
                .map(|(runtime, initialized)| (OnlineRuntime::Regtest(runtime), initialized))
        }
        (WcashChain::Regtest, None) => {
            WcashRegtestRuntime::create(endpoint, wallet_path, master_seed)
                .await
                .map(|(runtime, initialized)| (OnlineRuntime::Regtest(runtime), initialized))
        }
    }
    .map_err(|error| error.to_string())
}

fn wallet_info(initialized: InitializedWallet) -> WalletInfo {
    WalletInfo {
        account_id: initialized.account_id,
        birthday_height: initialized.birthday_height,
        address: initialized.address,
        transparent_coinbase_address: initialized.transparent_coinbase_address,
    }
}

/// Parses one REPL line with the upstream clap grammar and Wcash recipient validation seam.
pub(super) fn parse_command_tokens(tokens: &[String]) -> Result<CliCommand, String> {
    let command = if tokens.first().is_some_and(|name| name == "send") {
        let command = CliCommand::Send {
            args: tokens[COMMAND_NAME_COUNT..].to_vec(),
        };
        validate_deferred_grammar(&command)?;
        command
    } else {
        crate::commands::parse_command_tokens(tokens)?
    };
    if supported_command(&command) {
        Ok(command)
    } else {
        Err(format!(
            "Command {} is not available in Wcash Wallet",
            command.name()
        ))
    }
}

fn supported_command(command: &CliCommand) -> bool {
    matches!(
        command,
        CliCommand::Addresses
            | CliCommand::Balance
            | CliCommand::Birthday
            | CliCommand::Calculate
            | CliCommand::Confirm
            | CliCommand::Height
            | CliCommand::Help { .. }
            | CliCommand::Quit
            | CliCommand::RecoveryInfo
            | CliCommand::Save { .. }
            | CliCommand::Send { .. }
            | CliCommand::Shield
            | CliCommand::Sync {
                sub: SyncSubCommand::Run
            }
            | CliCommand::TAddresses
            | CliCommand::Transactions
            | CliCommand::Version
            | CliCommand::WalletKind
    )
}

/// Runs the Wcash-aware deferred grammar checks for one parsed command.
pub(super) fn validate_deferred_grammar(command: &CliCommand) -> Result<(), String> {
    match command {
        CliCommand::Send { args } => parse_send_args(args)
            .map(drop)
            .map_err(|error| format!("{error}\nTry 'help `send`' for correct usage and examples.")),
        _ => command.validate_deferred_grammar(),
    }
}

#[allow(clippy::disallowed_methods)]
fn command_loop(mut session: WcashCliSession, communications: Communications) -> CommandChannel {
    let (command_transmitter, command_receiver) = channel::<Request>();
    let (response_transmitter, response_receiver) = channel::<Result<String, String>>();

    std::thread::spawn(move || {
        while let Ok(request) = command_receiver.recv() {
            let command = match request {
                Request::Command(command) => command,
                Request::PromptIndicator => {
                    if response_transmitter
                        .send(Ok(session.prompt_indicator()))
                        .is_err()
                    {
                        break;
                    }
                    continue;
                }
                Request::AwaitSync => {
                    let response = session
                        .last_sync
                        .take()
                        .ok_or_else(|| "Error: no sync task is running to wait for".to_string());
                    if response_transmitter.send(response).is_err() {
                        break;
                    }
                    continue;
                }
            };

            if let CliCommand::Help { command } = &command {
                if response_transmitter
                    .send(Ok(format_help(command.as_deref())))
                    .is_err()
                {
                    break;
                }
                continue;
            }
            if let Some(refusal) = offline_mode_refusal(communications, &command) {
                if response_transmitter.send(Err(refusal)).is_err() {
                    break;
                }
                continue;
            }

            let is_quit = matches!(command, CliCommand::Quit);
            let response =
                dispatch(command, &mut session).map_err(|error| format!("Error: {error}"));
            if response_transmitter.send(response).is_err() || is_quit {
                break;
            }
        }
    });

    CommandChannel {
        transmitter: command_transmitter,
        receiver: response_receiver,
    }
}

fn dispatch(command: CliCommand, session: &mut WcashCliSession) -> Result<String, String> {
    match command {
        CliCommand::Addresses => render_addresses(&session.info),
        CliCommand::Balance => render_balance(&session.balance()?),
        CliCommand::Birthday => Ok(session.info.birthday_height.to_string()),
        CliCommand::Height => Ok(json::object! {
            "height" => session.balance()?.chain_tip_height,
        }
        .pretty(JSON_INDENT)),
        CliCommand::Calculate => calculate(session),
        CliCommand::Confirm => confirm(session),
        CliCommand::RecoveryInfo => recovery_info(session),
        CliCommand::Save { sub } => save(sub),
        CliCommand::Send { args } => send(&args, session),
        CliCommand::Shield => shield(session),
        CliCommand::Sync {
            sub: SyncSubCommand::Run,
        } => {
            session.last_sync = Some(session.sync()?);
            Ok("Launching sync task...".to_string())
        }
        CliCommand::TAddresses => render_transparent_addresses(&session.info),
        CliCommand::Transactions => render_transactions(
            session.chain.confirmed_transactions(&session.wallet_path)?,
            session
                .chain
                .active_pending_transactions(&session.wallet_path)?,
            session
                .calculated
                .as_ref()
                .map(|calculated| calculated.signed().txid.as_str()),
            &session.transmitted_txids,
        ),
        CliCommand::Help { command } => Ok(format_help(command.as_deref())),
        CliCommand::Version => Ok(zingolib::git_description().to_string()),
        CliCommand::Quit => Ok("Wcash Wallet quit successfully.".to_string()),
        CliCommand::WalletKind => wallet_kind(session),
        unsupported => Err(format!(
            "the `{}` command is outside the first Wcash CLI compatibility slice",
            unsupported.name()
        )),
    }
}

fn send(args: &[String], session: &mut WcashCliSession) -> Result<String, String> {
    require_no_calculated_transaction(session.calculated.is_some())?;
    let payments = parse_send_args(args)?;
    for payment in &payments {
        session.chain.validate_recipient(&payment.address)?;
    }
    cancel_proposal(session)?;
    let proposal = session.chain.propose_send(&session.wallet_path, payments)?;
    let fee = proposal.fee_zat();
    session.proposal = Some(proposal);
    Ok(json::object! { "fee" => fee }.pretty(JSON_INDENT))
}

fn shield(session: &mut WcashCliSession) -> Result<String, String> {
    require_no_calculated_transaction(session.calculated.is_some())?;
    cancel_proposal(session)?;
    let proposal = session.chain.propose_shield(&session.wallet_path)?;
    let fee = proposal.fee_zat();
    let value_to_shield = proposal
        .value_to_shield_zat()
        .ok_or_else(|| "the Wcash shielding proposal has no selected value".to_string())?;
    session.proposal = Some(proposal);
    Ok(json::object! {
        "value_to_shield" => value_to_shield,
        "fee" => fee,
    }
    .pretty(JSON_INDENT))
}

fn require_no_calculated_transaction(calculated: bool) -> Result<(), String> {
    if calculated {
        Err(
            "the calculated transaction must be confirmed before another proposal is created"
                .to_string(),
        )
    } else {
        Ok(())
    }
}

fn cancel_proposal(session: &mut WcashCliSession) -> Result<(), String> {
    if let Some(proposal) = session.proposal.as_ref() {
        session
            .chain
            .cancel(&session.wallet_path, proposal)
            .map_err(|error| format!("the prior proposal could not be cancelled: {error}"))?;
    }
    session.proposal = None;
    Ok(())
}

fn confirm(session: &mut WcashCliSession) -> Result<String, String> {
    let calculated = session
        .calculated
        .as_ref()
        .ok_or_else(|| "no calculated proposal is ready to confirm".to_string())?;
    let runtime = session
        .runtime
        .as_mut()
        .ok_or_else(|| "confirm requires an online Wcash session".to_string())?;
    let result = RT.block_on(runtime.broadcast_calculated(calculated))?;
    let rendered = json::object! {
        "txids" => json::JsonValue::Array(vec![json::JsonValue::from(result.txid.as_str())]),
    }
    .pretty(JSON_INDENT);
    session.calculated = None;
    session.transmitted_txids.insert(result.txid);
    Ok(rendered)
}

fn calculate(session: &mut WcashCliSession) -> Result<String, String> {
    let phrase = session.credentials.load()?.ok_or_else(|| {
        "the recovery phrase is missing from the platform credential store. Open once with --seed and --birthday to restore signing access"
            .to_string()
    })?;
    let master_seed = master_seed_from_phrase(phrase.expose_secret())?;
    let proposal = session
        .proposal
        .as_ref()
        .ok_or_else(|| "no stored proposal is ready to calculate".to_string())?;
    let calculated = session
        .chain
        .calculate(&session.wallet_path, &master_seed, proposal)?;
    let txid = calculated.signed().txid.as_str();
    let rendered = json::object! {
        "txids" => json::JsonValue::Array(vec![json::JsonValue::from(txid)]),
    }
    .pretty(JSON_INDENT);
    session.proposal = None;
    session.calculated = Some(calculated);
    Ok(rendered)
}

fn recovery_info(session: &WcashCliSession) -> Result<String, String> {
    let phrase = session.credentials.load()?.ok_or_else(|| {
        "no mnemonic found in the platform credential store for this wallet".to_string()
    })?;
    Ok(zingolib::wallet::RecoveryInfo {
        seed_phrase: phrase.expose_secret().to_string(),
        birthday: u64::from(session.info.birthday_height),
        no_of_accounts: WALLET_ACCOUNT_COUNT,
    }
    .to_string())
}

fn save(sub: SaveSubCommand) -> Result<String, String> {
    Ok(match sub {
        SaveSubCommand::Run => "Wallet state is already persisted.".to_string(),
        SaveSubCommand::Check => String::new(),
        SaveSubCommand::Shutdown => "No save task was running.".to_string(),
    })
}

fn wallet_kind(session: &WcashCliSession) -> Result<String, String> {
    let has_mnemonic = session.credentials.load()?.is_some();
    Ok(if has_mnemonic {
        json::object! {
            "kind" => "Loaded from mnemonic (seed or phrase)",
            "transparent" => true,
            "sapling" => false,
            "orchard" => true,
        }
    } else {
        json::object! {
            "kind" => "No spending authority found",
            "transparent" => true,
            "sapling" => false,
            "orchard" => true,
        }
    }
    .pretty(WALLET_KIND_JSON_INDENT))
}

fn parse_send_args(args: &[String]) -> Result<Vec<WcashTestnetPayment>, String> {
    match args {
        [address, amount] => Ok(vec![payment(address, amount, None)?]),
        [address, amount, memo] => Ok(vec![payment(address, amount, Some(memo))?]),
        [json] => parse_send_json(json),
        _ => Err(
            "send expects an address and amount, with an optional memo, or one JSON array"
                .to_string(),
        ),
    }
}

fn parse_send_json(encoded: &str) -> Result<Vec<WcashTestnetPayment>, String> {
    let value: serde_json::Value = serde_json::from_str(encoded)
        .map_err(|_| "send arguments are not valid JSON".to_string())?;
    let entries = value
        .as_array()
        .filter(|entries| !entries.is_empty())
        .ok_or_else(|| "send expects a nonempty JSON array".to_string())?;
    entries
        .iter()
        .map(|entry| {
            let address = entry
                .get("address")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| "each send entry requires a string address".to_string())?;
            let amount = entry
                .get("amount")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| "each send entry requires a u64 amount".to_string())?;
            let memo = match entry.get("memo") {
                Some(value) => Some(
                    value
                        .as_str()
                        .ok_or_else(|| "each send memo must be a string".to_string())?,
                ),
                None => None,
            };
            payment_from_amount(address, amount, memo)
        })
        .collect()
}

fn payment(
    address: &str,
    encoded_amount: &str,
    memo: Option<&String>,
) -> Result<WcashTestnetPayment, String> {
    let amount = encoded_amount
        .trim()
        .parse::<u64>()
        .map_err(|_| "send amount must be a u64".to_string())?;
    payment_from_amount(address, amount, memo.map(String::as_str))
}

fn payment_from_amount(
    address: &str,
    amount_zat: u64,
    memo: Option<&str>,
) -> Result<WcashTestnetPayment, String> {
    Zatoshis::from_u64(amount_zat)
        .map_err(|_| "send amount exceeds the money range".to_string())?;
    let memo = memo.map_or_else(
        || Ok(Vec::new()),
        |memo| {
            MemoBytes::from_bytes(memo.as_bytes())
                .map(|_| memo.as_bytes().to_vec())
                .map_err(|_| "send memo exceeds 512 bytes".to_string())
        },
    )?;
    Ok(WcashTestnetPayment {
        address: address.to_string(),
        amount_zat,
        memo,
    })
}

fn render_addresses(info: &WalletInfo) -> Result<String, String> {
    Ok(json::JsonValue::Array(vec![json::object! {
        "account" => ACCOUNT_INDEX,
        "address_index" => ADDRESS_INDEX,
        "has_orchard" => true,
        "has_sapling" => false,
        "has_transparent" => false,
        "encoded_address" => info.address.as_str(),
    }])
    .pretty(JSON_INDENT))
}

fn render_transparent_addresses(info: &WalletInfo) -> Result<String, String> {
    Ok(json::JsonValue::Array(vec![json::object! {
        "account" => ACCOUNT_INDEX,
        "address_index" => ADDRESS_INDEX,
        "scope" => "external",
        "encoded_address" => info.transparent_coinbase_address.as_str(),
    }])
    .pretty(JSON_INDENT))
}

fn render_balance(summary: &WalletBalanceSummary) -> Result<String, String> {
    let account = summary
        .accounts
        .first()
        .ok_or_else(|| "the Wcash wallet has no account balance".to_string())?;
    let pending_ironwood = account
        .ironwood_pending_change_zat
        .checked_add(account.ironwood_pending_spendability_zat)
        .ok_or_else(|| "the Wcash Ironwood pending balance overflowed".to_string())?;
    let confirmed_ironwood = account
        .ironwood_total_zat
        .checked_sub(pending_ironwood)
        .ok_or_else(|| "the Wcash Ironwood balance is inconsistent".to_string())?;
    let confirmed_transparent = account
        .transparent_total_zat
        .checked_sub(account.transparent_coinbase_pending_zat)
        .ok_or_else(|| "the Wcash transparent balance is inconsistent".to_string())?;

    Ok(AccountBalance {
        confirmed_ironwood_balance: Some(zatoshis(confirmed_ironwood)?),
        unconfirmed_ironwood_balance: Some(zatoshis(pending_ironwood)?),
        total_ironwood_balance: Some(zatoshis(account.ironwood_total_zat)?),
        confirmed_orchard_balance: Some(zatoshis(account.orchard_total_zat)?),
        unconfirmed_orchard_balance: Some(zatoshis(NO_POOL_VALUE)?),
        total_orchard_balance: Some(zatoshis(account.orchard_total_zat)?),
        confirmed_sapling_balance: Some(zatoshis(account.sapling_total_zat)?),
        unconfirmed_sapling_balance: Some(zatoshis(NO_POOL_VALUE)?),
        total_sapling_balance: Some(zatoshis(account.sapling_total_zat)?),
        confirmed_transparent_balance: Some(zatoshis(confirmed_transparent)?),
        unconfirmed_transparent_balance: Some(zatoshis(account.transparent_coinbase_pending_zat)?),
        total_transparent_balance: Some(zatoshis(account.transparent_total_zat)?),
    }
    .to_string())
}

fn zatoshis(amount: u64) -> Result<Zatoshis, String> {
    Zatoshis::from_u64(amount).map_err(|_| "the Wcash balance exceeds the money range".to_string())
}

fn render_transactions(
    history: ConfirmedTransactionSummaryHistory,
    pending: PendingSignedTransactionPage,
    calculated_txid: Option<&str>,
    transmitted_txids: &HashSet<String>,
) -> Result<String, String> {
    let confirmed = history
        .transactions
        .into_iter()
        .map(|summary| {
            let value_zat = summary.value_zat;
            let transaction = summary.transaction;
            let kind = match (transaction.direction, transaction.kind) {
                (ConfirmedTransactionDirection::Incoming, _) => TransactionKind::Received,
                (_, ConfirmedTransactionKind::Shielding) => TransactionKind::Sent(SendType::Shield),
                (ConfirmedTransactionDirection::Internal, _) => {
                    TransactionKind::Sent(SendType::SendToSelf)
                }
                (ConfirmedTransactionDirection::Outgoing, _) => {
                    TransactionKind::Sent(SendType::Send)
                }
            };
            let pools_sent_from = match (transaction.direction, transaction.kind) {
                (ConfirmedTransactionDirection::Incoming, _) => Vec::new(),
                (_, ConfirmedTransactionKind::Shielding) => vec![PoolType::TRANSPARENT],
                _ => vec![PoolType::IRONWOOD],
            };
            let rendered = TransactionSummaries::new(vec![TransactionSummary {
                txid: txid_from_hex_encoded_str(&transaction.txid)
                    .map_err(|error| error.to_string())?,
                datetime: transaction.timestamp.unwrap_or(UNKNOWN_TIMESTAMP),
                status: ConfirmationStatus::Confirmed(BlockHeight::from_u32(
                    transaction.mined_height,
                )),
                blockheight: BlockHeight::from_u32(transaction.mined_height),
                kind,
                value: value_zat.unwrap_or(NO_POOL_VALUE),
                fee: transaction.fee_zat,
                zec_price: None,
                pools_sent_from,
                ironwood_notes: Vec::new(),
                orchard_notes: Vec::new(),
                sapling_notes: Vec::new(),
                transparent_coins: Vec::new(),
                outgoing_ironwood_notes: Vec::new(),
                outgoing_orchard_notes: Vec::new(),
                outgoing_sapling_notes: Vec::new(),
                outgoing_transparent_coins: Vec::new(),
            }])
            .to_string();
            Ok(if value_zat.is_some() {
                rendered
            } else {
                rendered.replacen(ZERO_VALUE_LINE, UNKNOWN_VALUE_LINE, ONE_REPLACEMENT)
            })
        })
        .collect::<Result<String, String>>()?;
    let pending = render_pending_transactions(pending, calculated_txid, transmitted_txids)?;
    Ok(format!("{pending}{confirmed}"))
}

fn render_pending_transactions(
    pending: PendingSignedTransactionPage,
    calculated_txid: Option<&str>,
    transmitted_txids: &HashSet<String>,
) -> Result<String, String> {
    if pending.exact_tip.is_none() {
        return Err("active pending transactions have no attested wallet tip".to_string());
    }
    let mut rendered = String::new();
    for transaction in pending.transactions.into_iter().rev() {
        txid_from_hex_encoded_str(&transaction.txid).map_err(|error| error.to_string())?;
        let status = if transmitted_txids.contains(&transaction.txid) {
            "transmitted"
        } else if calculated_txid == Some(transaction.txid.as_str()) {
            "calculated"
        } else {
            "calculated or transmitted"
        };
        rendered.push_str(&format!(
            "\n{{
    txid: {}
    datetime: not available
    status: {status}
    blockheight: not available
    kind: not available
    value: not available
    fee: not available
    zec price: not available
    pools sent from: not available
    ironwood notes: []
    orchard notes: []
    sapling notes: []
    transparent coins: []
    outgoing ironwood notes: []
    outgoing orchard notes: []
    outgoing sapling notes: []
    outgoing transparent coins: []
}}",
            transaction.txid
        ));
    }
    Ok(rendered)
}

fn render_sync(start_height: u32, summary: &WalletBalanceSummary) -> String {
    let blocks_scanned = summary.fully_scanned_height.saturating_sub(start_height);
    let percentage = if summary.synchronized {
        COMPLETE_PERCENTAGE.to_string()
    } else {
        "not available".to_string()
    };
    format!(
        "Sync completed succesfully:\n{{\n    sync start height: {start_height}\n    sync end height: {}\n    blocks scanned: {blocks_scanned}\n    sapling outputs scanned: {NO_SCANNED_LEGACY_OUTPUTS}\n    orchard outputs scanned: {NO_SCANNED_LEGACY_OUTPUTS}\n    ironwood outputs scanned: not available\n    percentage total outputs scanned: {percentage}\n}}",
        summary.fully_scanned_height
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_ACCOUNT_ID: &str = "account";
    const TEST_BIRTHDAY: u32 = 1;
    const TEST_PAYMENT_ZAT: u64 = 42;
    const MAX_MEMO_BYTES: usize = 512;
    const TEST_IRONWOOD_ADDRESS: &str = "waswo";
    const TEST_TRANSPARENT_ADDRESS: &str = "WTtest";
    const TEST_PHRASE: &str = "test recovery phrase";

    fn session(directory: &Path) -> WcashCliSession {
        WcashCliSession {
            chain: WcashChain::Testnet,
            wallet_path: WcashChain::Testnet.wallet_path(directory),
            runtime: None,
            credentials: CredentialStore::for_test(TEST_PHRASE),
            proposal: None,
            calculated: None,
            transmitted_txids: HashSet::new(),
            info: WalletInfo {
                account_id: TEST_ACCOUNT_ID.to_string(),
                birthday_height: TEST_BIRTHDAY,
                address: TEST_IRONWOOD_ADDRESS.to_string(),
                transparent_coinbase_address: TEST_TRANSPARENT_ADDRESS.to_string(),
            },
            last_sync: None,
        }
    }

    #[test]
    fn wcash_chain_selection_rejects_mainnet() {
        assert_eq!(
            WcashChain::from_chain_type(&ChainType::Testnet).unwrap(),
            WcashChain::Testnet
        );
        assert!(WcashChain::from_chain_type(&ChainType::Mainnet).is_err());
    }

    #[test]
    fn wcash_network_wallet_paths_are_disjoint() {
        let directory = tempfile::tempdir().unwrap();
        assert_ne!(
            WcashChain::Testnet.wallet_path(directory.path()),
            WcashChain::Regtest.wallet_path(directory.path())
        );
    }

    #[test]
    fn credential_accounts_are_bound_to_the_wallet_path_and_network() {
        let directory = tempfile::tempdir().unwrap();
        let wallet_path = directory.path().join("wallet.sqlite3");
        let testnet = CredentialStore::for_wallet(WcashChain::Testnet, &wallet_path);
        let regtest = CredentialStore::for_wallet(WcashChain::Regtest, &wallet_path);
        let other_path = CredentialStore::for_wallet(
            WcashChain::Testnet,
            &directory.path().join("other.sqlite3"),
        );

        assert_ne!(testnet.account, regtest.account);
        assert_ne!(testnet.account, other_path.account);
    }

    #[test]
    fn credential_store_failure_names_the_required_platform_service() {
        let error = credential_error(keyring::Error::NoDefaultStore);

        assert!(error.contains(CREDENTIAL_STORE_DESCRIPTION));
        assert!(error.contains("Wcash recovery phrase"));
    }

    #[test]
    fn visible_upstream_names_are_rebranded() {
        let help = brand_help("ZingoLabs Zingo CLI Zcash ZEC".to_string());

        assert_eq!(help, "Wcash Wallet Wcash Wallet Wcash Wcash");
    }

    #[test]
    fn first_slice_dispatch_keeps_upstream_address_fields() {
        let directory = tempfile::tempdir().unwrap();
        let mut session = session(directory.path());
        let addresses = dispatch(CliCommand::Addresses, &mut session).unwrap();
        let transparent = dispatch(CliCommand::TAddresses, &mut session).unwrap();
        let addresses: serde_json::Value = serde_json::from_str(&addresses).unwrap();
        let transparent: serde_json::Value = serde_json::from_str(&transparent).unwrap();

        assert_eq!(addresses[ACCOUNT_INDEX as usize]["account"], ACCOUNT_INDEX);
        assert_eq!(
            addresses[ACCOUNT_INDEX as usize]["encoded_address"],
            TEST_IRONWOOD_ADDRESS
        );
        assert_eq!(transparent[ACCOUNT_INDEX as usize]["scope"], "external");
        assert_eq!(
            transparent[ACCOUNT_INDEX as usize]["encoded_address"],
            TEST_TRANSPARENT_ADDRESS
        );
    }

    #[test]
    fn first_slice_dispatch_keeps_lifecycle_commands() {
        let directory = tempfile::tempdir().unwrap();
        let mut session = session(directory.path());

        assert_eq!(
            dispatch(CliCommand::Birthday, &mut session).unwrap(),
            TEST_BIRTHDAY.to_string()
        );
        assert!(
            !dispatch(CliCommand::Version, &mut session)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            dispatch(CliCommand::Quit, &mut session).unwrap(),
            "Wcash Wallet quit successfully."
        );
    }

    #[test]
    fn recovery_info_uses_the_platform_credential_shape() {
        let directory = tempfile::tempdir().unwrap();
        let mut session = session(directory.path());
        let info = dispatch(CliCommand::RecoveryInfo, &mut session).unwrap();

        assert!(info.contains(TEST_PHRASE));
        assert!(info.contains(&TEST_BIRTHDAY.to_string()));
    }

    #[test]
    fn unsupported_command_is_rejected_before_dispatch() {
        let error = parse_command_tokens(&["info".to_string()]).unwrap_err();

        assert!(error.contains("not available"));
    }

    #[test]
    fn help_lists_only_routed_commands_and_no_zcash_examples() {
        let help = format_help(None);
        let invalid = [
            "ztestsapling",
            "tmSwk8",
            "zennies_for_zingo",
            "$ZINGO_NYM_PROXY",
            "viewkey",
            "Server-Selection Sweep",
            r#"Defaults to "mainnet""#,
        ];

        for command in SUPPORTED_COMMAND_NAMES {
            assert!(help.contains(command));
            let command_help = format_help(Some(command));
            for invalid_text in invalid {
                assert!(
                    !command_help.contains(invalid_text),
                    "unexpected {command} help text: {invalid_text}"
                );
            }
        }
        for invalid_text in invalid {
            assert!(
                !help.contains(invalid_text),
                "unexpected help text: {invalid_text}"
            );
        }
    }

    #[test]
    fn send_parser_keeps_the_upstream_direct_and_json_grammar() {
        let direct = parse_send_args(&[
            TEST_IRONWOOD_ADDRESS.to_string(),
            TEST_PAYMENT_ZAT.to_string(),
            "memo".to_string(),
        ])
        .unwrap();
        let json = parse_send_args(&[format!(
            "[{{\"address\":\"{TEST_IRONWOOD_ADDRESS}\",\"amount\":{TEST_PAYMENT_ZAT},\"memo\":\"memo\"}}]"
        )])
        .unwrap();

        assert_eq!(direct, json);
    }

    #[test]
    fn send_parser_rejects_empty_json_and_oversized_memos() {
        assert!(parse_send_args(&["[]".to_string()]).is_err());
        assert!(
            parse_send_args(&[
                TEST_IRONWOOD_ADDRESS.to_string(),
                TEST_PAYMENT_ZAT.to_string(),
                "x".repeat(MAX_MEMO_BYTES + COMMAND_NAME_COUNT),
            ])
            .is_err()
        );
    }

    #[test]
    fn a_calculated_transaction_blocks_replacement_proposals() {
        let error = require_no_calculated_transaction(true).unwrap_err();

        assert!(error.contains("must be confirmed"));
        assert!(require_no_calculated_transaction(false).is_ok());
    }

    #[test]
    fn pending_transactions_remain_visible_with_truthful_unknown_fields() {
        let txid = "11".repeat(32);
        let pending = PendingSignedTransactionPage {
            exact_tip: Some(zingolib::wcash::BlockRef {
                height: 300,
                hash: [0x22; 32],
            }),
            transactions: vec![StoredSignedTransaction {
                txid: txid.clone(),
                raw_transaction_hex: String::new(),
                branch_id: String::new(),
                expiry_height: 340,
            }],
            next_after_row_id: None,
        };
        let transmitted = HashSet::from([txid.clone()]);
        let rendered = render_pending_transactions(pending, None, &transmitted).unwrap();

        assert!(rendered.contains(&format!("txid: {txid}")));
        assert!(rendered.contains("status: transmitted"));
        assert!(rendered.contains("blockheight: not available"));
        assert!(rendered.contains("value: not available"));
    }

    #[test]
    fn confirmed_transactions_use_backend_kind_and_display_value() {
        const TXID_BYTE_COUNT: usize = 32;
        const MINED_HEIGHT: u32 = 95;
        const TIP_HEIGHT: u32 = 100;
        const TIP_HASH_BYTE: u8 = 0x44;
        const CONFIRMATIONS: u32 = TIP_HEIGHT - MINED_HEIGHT + 1;
        const SHIELD_DELTA_ZAT: i64 = -20_000;
        const SHIELD_FEE_ZAT: u64 = 20_000;
        const SHIELD_VALUE_ZAT: u64 = 1_249_980_000;
        const SEND_DELTA_ZAT: i64 = -110_000;
        const SEND_FEE_ZAT: u64 = 10_000;
        const SEND_VALUE_ZAT: u64 = 100_000;

        let shield_txid = "22".repeat(TXID_BYTE_COUNT);
        let send_txid = "33".repeat(TXID_BYTE_COUNT);
        let metadata_poor_txid = "44".repeat(TXID_BYTE_COUNT);
        let transaction = |txid, kind, delta, fee| zingolib::wcash::ConfirmedTransaction {
            txid,
            mined_height: MINED_HEIGHT,
            direction: if kind == ConfirmedTransactionKind::Shielding {
                ConfirmedTransactionDirection::Internal
            } else {
                ConfirmedTransactionDirection::Outgoing
            },
            kind,
            amount_delta_zat: delta,
            fee_zat: fee,
            timestamp: None,
            confirmations: CONFIRMATIONS,
        };
        let history = ConfirmedTransactionSummaryHistory {
            exact_tip: zingolib::wcash::BlockRef {
                height: TIP_HEIGHT,
                hash: [TIP_HASH_BYTE; TXID_BYTE_COUNT],
            },
            transactions: vec![
                zingolib::wcash::ConfirmedTransactionSummary {
                    transaction: transaction(
                        shield_txid.clone(),
                        ConfirmedTransactionKind::Shielding,
                        SHIELD_DELTA_ZAT,
                        Some(SHIELD_FEE_ZAT),
                    ),
                    value_zat: Some(SHIELD_VALUE_ZAT),
                },
                zingolib::wcash::ConfirmedTransactionSummary {
                    transaction: transaction(
                        send_txid.clone(),
                        ConfirmedTransactionKind::Transfer,
                        SEND_DELTA_ZAT,
                        Some(SEND_FEE_ZAT),
                    ),
                    value_zat: Some(SEND_VALUE_ZAT),
                },
                zingolib::wcash::ConfirmedTransactionSummary {
                    transaction: transaction(
                        metadata_poor_txid.clone(),
                        ConfirmedTransactionKind::Transfer,
                        SEND_DELTA_ZAT,
                        None,
                    ),
                    value_zat: None,
                },
            ],
        };
        let pending = PendingSignedTransactionPage {
            exact_tip: Some(history.exact_tip),
            transactions: Vec::new(),
            next_after_row_id: None,
        };

        let rendered = render_transactions(history, pending, None, &HashSet::new()).unwrap();

        assert!(rendered.contains(&format!("txid: {shield_txid}")));
        assert!(rendered.contains("kind: shield"));
        assert!(rendered.contains("value: 1249980000"));
        assert!(rendered.contains(&format!("txid: {send_txid}")));
        assert!(rendered.contains("kind: sent"));
        assert!(rendered.contains("value: 100000"));
        let metadata_poor = rendered
            .find(&format!("txid: {metadata_poor_txid}"))
            .unwrap();
        assert!(rendered[metadata_poor..].contains("value: not available"));
    }
}
