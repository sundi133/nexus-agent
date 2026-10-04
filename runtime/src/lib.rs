pub mod action_client;
mod credentials;
pub use credentials::read_secret_file;
pub mod config;
pub mod device_credential;
pub mod http;
pub mod local_ingest;
pub mod mcp;
pub mod policy_store;
pub mod spool;
pub mod source;
pub mod worker;

pub use config::{ControlPlaneConfig, RuntimeConfig};
pub use http::{ControlPlaneTransport, HttpControlPlane, PolicyFetch};
pub use policy_store::{ActivatedPolicy, PolicyStore};
pub use spool::{DiskSpool, SpoolStats};
pub use worker::{RuntimeCycleReport, RuntimeWorker};

pub use source::{IngestStats, JsonlTailer};

pub use local_ingest::{spawn_local_ingest, AgentActionAuditRecord, LocalIngestAuth, ProducerAttestation, ProducerCredential};
#[cfg(unix)]
pub use local_ingest::spawn_local_ingest_unix;

#[cfg(windows)]
pub use local_ingest::spawn_local_ingest_windows_pipe;

pub use action_client::{authorize_action, AgentActionClient, LocalAuthorizationTarget};

pub use mcp::normalize_mcp_action;

pub use device_credential::{atomic_write_device_credential, load_device_credential, DeviceCredential, DeviceCredentialError};
