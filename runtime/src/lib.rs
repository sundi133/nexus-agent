mod credentials;
pub use credentials::read_secret_file;
pub mod config;
pub mod http;
pub mod local_ingest;
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
