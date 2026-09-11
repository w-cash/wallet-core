//! Wcash chain profiles exposed by the wallet library.

use wcash_wallet_core::{WcashGenesisHash, WcashNetwork};

/// The Wcash Testnet identity accepted by this release.
///
/// This release exposes the identity as compile-time constants. A Wcash
/// Mainnet profile can be added after its genesis and transaction domain are
/// frozen.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WcashTestnet;

impl WcashTestnet {
    /// Returns the Wcash wallet-core network selected by this profile.
    pub const fn network(self) -> WcashNetwork {
        WcashNetwork::Testnet
    }

    /// Returns the ticker for valueless test funds.
    pub const fn ticker(self) -> &'static str {
        self.network().currency_ticker()
    }

    /// Returns the frozen genesis block identifier in display byte order.
    pub const fn genesis_hash_display(self) -> &'static str {
        self.network().genesis_hash_display()
    }

    /// Returns the frozen genesis block identifier in internal byte order.
    pub const fn genesis_hash(self) -> WcashGenesisHash {
        self.network().genesis_hash()
    }

    /// Returns the Wcash transaction and signature domain.
    pub fn branch_id(self) -> u32 {
        self.network().branch_id().into()
    }

    /// Returns the wallet and block-cache namespace.
    pub const fn storage_namespace(self) -> &'static str {
        self.network().storage_namespace()
    }
}

#[cfg(test)]
mod tests {
    use zcash_protocol::consensus::BranchId;

    use super::*;

    const WCASH_TESTNET_TICKER: &str = "TWC";
    const WCASH_TESTNET_GENESIS_DISPLAY: &str =
        "0271b5b0a10b2838f43cccdec9ca2f72aa72a7c103830082bac8f82f47f0593a";
    const WCASH_TESTNET_BRANCH_ID: u32 = 0xb3cf_d27e;
    const WCASH_TESTNET_STORAGE_NAMESPACE: &str = "wcashtestnet-v5";
    const ZCASH_TESTNET_STORAGE_NAMESPACE: &str = "testnet3";
    const ZCASH_TICKER: &str = "ZEC";

    #[test]
    fn profile_matches_the_frozen_wcash_testnet_identity() {
        let profile = WcashTestnet;

        assert_eq!(profile.network(), WcashNetwork::Testnet);
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
}
