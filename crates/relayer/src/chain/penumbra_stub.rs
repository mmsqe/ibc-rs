// Stub module when Penumbra support is disabled
// This allows the code to compile without Penumbra SDK dependencies

pub mod config {
    use serde::{Deserialize, Serialize};
    use tendermint_rpc::Url;
    use core::time::Duration;
    use ibc_relayer_types::core::ics24_host::identifier::ChainId;
    use ibc_relayer_types::core::ics02_client::trust_threshold::TrustThreshold;
    use crate::config::{PacketFilter, RefreshRate, GenesisRestart, EventSourceMode, compat_mode::CompatMode};
    
    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
    pub struct PenumbraConfig {
        pub stub_key_name: String,
        pub id: ChainId,
        pub grpc_addr: Url,
        pub rpc_addr: Url,
        pub event_source: EventSourceMode,
        pub rpc_timeout: Duration,
        pub packet_filter: PacketFilter,
        pub clear_interval: Option<u64>,
        pub query_packets_chunk_size: usize,
        pub max_block_time: Duration,
        pub genesis_restart: Option<GenesisRestart>,
        pub clock_drift: Duration,
        pub client_refresh_rate: RefreshRate,
        pub trust_threshold: TrustThreshold,
        pub compat_mode: Option<CompatMode>,
        pub view_service_storage_dir: Option<String>,
        pub kms_config: KmsConfig,
    }
    
    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
    pub struct KmsConfig {
        // Stub for KMS config
    }
}

pub mod util {
    use crate::config::compat_mode::CompatMode;
    use crate::error::Error;
    use tendermint::Version;
    
    pub fn compat_mode_from_version(_compat_mode: &Option<CompatMode>, _version: Version) -> Result<CompatMode, Error> {
        // When Penumbra support is disabled, return a default CompatMode
        Ok(CompatMode::V0_34)
    }
}

pub mod version {
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Specs;
}

// Stub type to satisfy compile requirements
pub struct PenumbraChain;
