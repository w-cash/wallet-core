//! Wcash session routing for the upstream Zingo command surface.

use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::mpsc::channel;

use bip0039::{Count, English, Mnemonic};
use secrecy::SecretVec;
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
use zingolib::wcash::{
    BroadcastResult, ConfirmedTransactionDirection, ConfirmedTransactionHistory,
    ConfirmedTransactionKind, InitializedWallet, MAX_CONFIRMED_TRANSACTION_HISTORY_SIZE,
    PendingSignedTransactionPage, SignedTransaction, StoredSignedTransaction, WalletBalanceSummary,
    WalletInfo, WalletSyncCancellation, WcashRegtest, WcashRegtestRuntime, WcashTestnet,
    WcashTestnetPayment, WcashTestnetRuntime,
};

use crate::commands::{CliCommand, RT, SyncSubCommand};
use crate::{
    CliConfigTemplate, CommandChannel, Communications, Operations, Request, offline_mode_refusal,
    start_interactive, start_noninteractive,
};

const WALLET_FILE_EXTENSION: &str = "sqlite3";
const ACCOUNT_INDEX: u32 = u32::MIN;
const ADDRESS_INDEX: u32 = u32::MIN;
const UNKNOWN_TIMESTAMP: u32 = u32::MIN;
const NO_POOL_VALUE: u64 = u64::MIN;
const NO_SCANNED_LEGACY_OUTPUTS: u32 = u32::MIN;
const COMPLETE_PERCENTAGE: u32 = 100;
const FIRST_CHAIN_HEIGHT: u32 = 1;
const CONFIRM_PAGE_SIZE: usize = 1;
const COMMAND_NAME_COUNT: usize = 1;
const JSON_INDENT: u16 = 2;

/// Applies Wcash product and asset names to the upstream clap help tree.
pub(super) fn brand_clap_command(mut command: clap::Command) -> clap::Command {
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
        match (&cli_config.server, self) {
            (Some(server), _) => Ok(Some(server.to_string())),
            (None, Self::Testnet) => Ok(Some(WcashTestnet.default_endpoint().to_string())),
            (None, Self::Regtest) => {
                Err("Wcash Regtest requires an explicit --server endpoint".to_string())
            }
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
    ) -> Result<ConfirmedTransactionHistory, String> {
        match self {
            Self::Testnet => WcashTestnetRuntime::read_confirmed_transactions(
                wallet_path,
                MAX_CONFIRMED_TRANSACTION_HISTORY_SIZE,
            ),
            Self::Regtest => WcashRegtestRuntime::read_confirmed_transactions(
                wallet_path,
                MAX_CONFIRMED_TRANSACTION_HISTORY_SIZE,
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

    async fn send(
        &mut self,
        master_seed: &SecretVec<u8>,
        payments: Vec<WcashTestnetPayment>,
    ) -> Result<SignedTransaction, String> {
        match self {
            Self::Testnet(runtime) => runtime.send(master_seed, payments).await,
            Self::Regtest(runtime) => runtime.send(master_seed, payments).await,
        }
        .map_err(|error| error.to_string())
    }

    async fn shield_coinbase(
        &mut self,
        master_seed: &SecretVec<u8>,
    ) -> Result<SignedTransaction, String> {
        match self {
            Self::Testnet(runtime) => runtime.shield_coinbase(master_seed).await,
            Self::Regtest(runtime) => runtime.shield_coinbase(master_seed).await,
        }
        .map_err(|error| error.to_string())
    }

    fn active_pending_transactions(&self) -> Result<PendingSignedTransactionPage, String> {
        match self {
            Self::Testnet(runtime) => {
                runtime.active_pending_transactions(None, None, CONFIRM_PAGE_SIZE)
            }
            Self::Regtest(runtime) => {
                runtime.active_pending_transactions(None, None, CONFIRM_PAGE_SIZE)
            }
        }
        .map_err(|error| error.to_string())
    }

    async fn broadcast_pending(
        &mut self,
        signed: &StoredSignedTransaction,
    ) -> Result<BroadcastResult, String> {
        match self {
            Self::Testnet(runtime) => runtime.broadcast_pending(signed).await,
            Self::Regtest(runtime) => runtime.broadcast_pending(signed).await,
        }
        .map_err(|error| error.to_string())
    }
}

struct WcashCliSession {
    chain: WcashChain,
    wallet_path: PathBuf,
    runtime: Option<OnlineRuntime>,
    master_seed: Option<SecretVec<u8>>,
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
        eprintln!("Standing Connectivity Consent forgotten; future sessions start offline again.");
    }

    let explicit_server =
        matches.value_source("server") == Some(clap::parser::ValueSource::CommandLine);
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
            "Standing Connectivity Consent stored in '{}'; future sessions attach to the network automatically. Undo with --forget-online.",
            data_dir
                .join(zingolib::connectivity::CONNECTIVITY_CONSENT_FILE)
                .display()
        );
    }

    if matches.get_flag("online") || remember_online || explicit_server || stored_online {
        Ok(Communications::Online)
    } else {
        eprintln!(
            "No Connectivity Consent is recorded, so this Wcash Wallet session runs offline. Pass --online, --remember-online, or --server <uri> to connect."
        );
        Ok(Communications::UnconsentedOffline)
    }
}

/// Returns the connectivity posture used to render pre-startup help.
pub(super) fn posture_preview(matches: &clap::ArgMatches) -> Communications {
    if matches.get_flag("offline") {
        return Communications::DeliberateOffline;
    }
    let explicit_server =
        matches.value_source("server") == Some(clap::parser::ValueSource::CommandLine);
    let stored_online = matches!(
        zingolib::connectivity::load_connectivity_consent(&super::data_dir_from(matches)),
        zingolib::connectivity::ConnectivityConsent::StandingOnline
    );
    if matches.get_flag("online")
        || matches.get_flag("remember-online")
        || explicit_server
        || stored_online
    {
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

    if cli_config.ufvk.is_some() {
        return Err("Wcash viewing-key restore is not available in this release".to_string());
    }

    let (runtime, info, generated_phrase, master_seed) = if wallet_path.exists() {
        let master_seed = cli_config
            .seed
            .as_deref()
            .map(master_seed_from_phrase)
            .transpose()?;
        let info = chain.inspect(&wallet_path)?;
        let runtime = endpoint
            .as_deref()
            .map(|endpoint| RT.block_on(open_runtime(chain, endpoint, &wallet_path)))
            .transpose()?;
        (runtime, info, None, master_seed)
    } else {
        let endpoint = endpoint
            .as_deref()
            .ok_or_else(|| "creating a Wcash wallet requires an online session".to_string())?;
        let supplied = cli_config.seed.as_deref();
        let mnemonic = supplied.map_or_else(
            || Ok(Mnemonic::<English>::generate(Count::Words24)),
            |phrase| Mnemonic::<English>::from_phrase(phrase).map_err(|error| error.to_string()),
        )?;
        let generated_phrase = supplied.is_none().then(|| mnemonic.phrase().to_string());
        let master_seed = SecretVec::new(mnemonic.to_seed("").as_slice().to_vec());
        let birthday = u32::try_from(cli_config.birthday)
            .map_err(|_| "the Wcash wallet birthday exceeds u32".to_string())?;
        let (runtime, initialized) = RT.block_on(initialize_runtime(
            chain,
            endpoint,
            &wallet_path,
            &master_seed,
            supplied.is_some().then_some(birthday),
        ))?;
        (
            Some(runtime),
            wallet_info(initialized),
            generated_phrase,
            Some(master_seed),
        )
    };

    if let Some(phrase) = generated_phrase {
        eprintln!("Wcash Wallet recovery phrase:\n{phrase}");
    }

    let mut session = WcashCliSession {
        chain,
        wallet_path,
        runtime,
        master_seed,
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
    if tokens.first().is_some_and(|name| name == "send") {
        let command = CliCommand::Send {
            args: tokens[COMMAND_NAME_COUNT..].to_vec(),
        };
        validate_deferred_grammar(&command)?;
        Ok(command)
    } else {
        crate::commands::parse_command_tokens(tokens)
    }
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
                    .send(Ok(brand_help(crate::commands::format_help(
                        communications,
                        command.as_deref(),
                    ))))
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
        CliCommand::Send { args } => send(&args, session),
        CliCommand::Shield => shield(session),
        CliCommand::Sync {
            sub: SyncSubCommand::Run,
        } => {
            session.last_sync = Some(session.sync()?);
            Ok("Launching sync task...".to_string())
        }
        CliCommand::TAddresses => render_transparent_addresses(&session.info),
        CliCommand::Transactions => {
            render_transactions(session.chain.confirmed_transactions(&session.wallet_path)?)
        }
        CliCommand::Help { command } => Ok(brand_help(crate::commands::format_help(
            if session.runtime.is_some() {
                Communications::Online
            } else {
                Communications::UnconsentedOffline
            },
            command.as_deref(),
        ))),
        CliCommand::Version => Ok(zingolib::git_description().to_string()),
        CliCommand::Quit => Ok("Wcash Wallet quit successfully.".to_string()),
        unsupported => Err(format!(
            "the `{}` command is outside the first Wcash CLI compatibility slice",
            unsupported.name()
        )),
    }
}

fn send(args: &[String], session: &mut WcashCliSession) -> Result<String, String> {
    let payments = parse_send_args(args)?;
    for payment in &payments {
        session.chain.validate_recipient(&payment.address)?;
    }
    let master_seed = session.master_seed.as_ref().ok_or_else(|| {
        "send requires the recovery phrase through --seed or WCASH_SEED for this session"
            .to_string()
    })?;
    let runtime = session
        .runtime
        .as_mut()
        .ok_or_else(|| "send requires an online Wcash session".to_string())?;
    let signed = RT.block_on(runtime.send(master_seed, payments))?;
    Ok(json::object! { "fee" => signed.fee_zat }.pretty(JSON_INDENT))
}

fn shield(session: &mut WcashCliSession) -> Result<String, String> {
    let value_before_fee = session
        .balance()?
        .accounts
        .first()
        .ok_or_else(|| "the Wcash wallet has no account balance".to_string())?
        .transparent_coinbase_spendable_zat;
    let master_seed = session.master_seed.as_ref().ok_or_else(|| {
        "shield requires the recovery phrase through --seed or WCASH_SEED for this session"
            .to_string()
    })?;
    let runtime = session
        .runtime
        .as_mut()
        .ok_or_else(|| "shield requires an online Wcash session".to_string())?;
    let signed = RT.block_on(runtime.shield_coinbase(master_seed))?;
    let value_to_shield = value_before_fee
        .checked_sub(signed.fee_zat)
        .ok_or_else(|| "the Wcash shielding fee exceeds the selected value".to_string())?;
    Ok(json::object! {
        "value_to_shield" => value_to_shield,
        "fee" => signed.fee_zat,
    }
    .pretty(JSON_INDENT))
}

fn confirm(session: &mut WcashCliSession) -> Result<String, String> {
    let runtime = session
        .runtime
        .as_mut()
        .ok_or_else(|| "confirm requires an online Wcash session".to_string())?;
    let page = runtime.active_pending_transactions()?;
    let signed = page
        .transactions
        .first()
        .ok_or_else(|| "no stored proposal is ready to confirm".to_string())?;
    let result = RT.block_on(runtime.broadcast_pending(signed))?;
    Ok(json::object! {
        "txids" => json::JsonValue::Array(vec![json::JsonValue::from(result.txid)]),
    }
    .pretty(JSON_INDENT))
}

fn calculate(session: &WcashCliSession) -> Result<String, String> {
    let runtime = session
        .runtime
        .as_ref()
        .ok_or_else(|| "calculate requires an online Wcash session".to_string())?;
    let page = runtime.active_pending_transactions()?;
    let txids = page
        .transactions
        .iter()
        .map(|transaction| transaction.txid.as_str())
        .collect::<Vec<_>>();
    if txids.is_empty() {
        return Err("no stored proposal is ready to calculate".to_string());
    }
    Ok(json::object! {
        "txids" => json::JsonValue::Array(
            txids.into_iter().map(json::JsonValue::from).collect()
        ),
    }
    .pretty(JSON_INDENT))
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

fn render_transactions(history: ConfirmedTransactionHistory) -> Result<String, String> {
    let summaries = history
        .transactions
        .into_iter()
        .map(|transaction| {
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
            Ok(TransactionSummary {
                txid: txid_from_hex_encoded_str(&transaction.txid)
                    .map_err(|error| error.to_string())?,
                datetime: transaction.timestamp.unwrap_or(UNKNOWN_TIMESTAMP),
                status: ConfirmationStatus::Confirmed(BlockHeight::from_u32(
                    transaction.mined_height,
                )),
                blockheight: BlockHeight::from_u32(transaction.mined_height),
                kind,
                value: transaction.amount_delta_zat.unsigned_abs(),
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
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(TransactionSummaries::new(summaries).to_string())
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

    fn session(directory: &Path) -> WcashCliSession {
        WcashCliSession {
            chain: WcashChain::Testnet,
            wallet_path: WcashChain::Testnet.wallet_path(directory),
            runtime: None,
            master_seed: None,
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
    fn unsupported_command_fails_at_the_wcash_dispatch_seam() {
        let directory = tempfile::tempdir().unwrap();
        let mut session = session(directory.path());
        let error = dispatch(CliCommand::RecoveryInfo, &mut session).unwrap_err();

        assert!(error.contains("recovery_info"));
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
}
