use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use thiserror::Error;

const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 5_000;
const DEFAULT_REQUEST_TIMEOUT_MS: u64 = 30_000;
const DEFAULT_SPOOL_MAX_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_SEGMENT_MAX_BYTES: u64 = 4 * 1024 * 1024;
const DEFAULT_CYCLE_INTERVAL_MS: u64 = 5_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeConfig {
    pub control_plane: ControlPlaneConfig,
    pub spool_dir: PathBuf,
    pub policy_signed_path: PathBuf,
    pub policy_watermark_path: PathBuf,
    pub policy_public_key_file: PathBuf,
    pub event_source_path: PathBuf,
    pub event_offset_path: PathBuf,
    pub health_source_path: PathBuf,
    pub local_ingest_port: Option<u16>,
    pub local_ingest_socket_path: Option<PathBuf>,
    pub local_ingest_pipe_name: Option<String>,
    pub local_ingest_token_file: Option<PathBuf>,
    #[serde(default)]
    pub local_ingest_producers: Vec<LocalProducerConfig>,
    #[serde(default = "default_cycle_interval_ms")]
    pub cycle_interval_ms: u64,
    #[serde(default = "default_spool_max_bytes")]
    pub spool_max_bytes: u64,
    #[serde(default = "default_segment_max_bytes")]
    pub segment_max_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalProducerConfig {
    pub agent_id: String,
    pub token_file: PathBuf,
    #[serde(default)]
    pub expected_uid: Option<u32>,
    #[serde(default)]
    pub executable_paths: Vec<PathBuf>,
    #[serde(default)]
    pub executable_sha256: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlPlaneConfig {
    pub policy_url: String,
    pub health_url: String,
    pub events_url: String,
    pub bearer_token_file: PathBuf,
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    #[serde(default = "default_request_timeout_ms")]
    pub request_timeout_ms: u64,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("invalid URL for {0}")]
    InvalidUrl(&'static str),
    #[error("{0} must use HTTPS")]
    InsecureUrl(&'static str),
    #[error("{0} may not contain embedded credentials or a fragment")]
    UnsafeUrl(&'static str),
    #[error("timeouts must be non-zero")]
    InvalidTimeout,
    #[error("spool limits are invalid")]
    InvalidSpoolLimits,
    #[error("local ingest configuration is invalid")]
    InvalidLocalIngest,
}

impl RuntimeConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.control_plane.validate()?;
        if self.segment_max_bytes == 0
            || self.spool_max_bytes == 0
            || self.segment_max_bytes > self.spool_max_bytes
            || self.cycle_interval_ms == 0
        {
            return Err(ConfigError::InvalidSpoolLimits);
        }

        let socket_path_present = self
            .local_ingest_socket_path
            .as_ref()
            .is_some_and(|path| !path.as_os_str().is_empty());
        let pipe_name_present = self
            .local_ingest_pipe_name
            .as_ref()
            .is_some_and(|name| !name.trim().is_empty() && name.len() <= 240);

        match (
            &self.local_ingest_port,
            socket_path_present,
            pipe_name_present,
            &self.local_ingest_token_file,
            self.local_ingest_producers.as_slice(),
        ) {
            (None, false, false, None, []) => {}
            (Some(port), false, false, Some(path), [])
                if *port >= 1024 && !path.as_os_str().is_empty() => {}
            (Some(port), false, false, None, producers)
                if *port >= 1024 && !producers.is_empty() => {
                    validate_local_producers(producers)?;
                }
            (None, true, false, None, producers) if !producers.is_empty() => {
                validate_local_producers(producers)?;
                require_peer_constraints(producers)?;
            }
            (None, false, true, None, producers) if !producers.is_empty() => {
                validate_local_producers(producers)?;
                require_peer_constraints(producers)?;
            }
            _ => return Err(ConfigError::InvalidLocalIngest),
        }

        Ok(())
    }
}

fn validate_local_producers(
    producers: &[LocalProducerConfig],
) -> Result<(), ConfigError> {
    if producers.len() > 64 {
        return Err(ConfigError::InvalidLocalIngest);
    }

    let mut ids = std::collections::HashSet::new();
    for producer in producers {
        if producer.agent_id.is_empty()
            || producer.agent_id.len() > 256
            || producer.token_file.as_os_str().is_empty()
            || !ids.insert(producer.agent_id.as_str())
            || producer.executable_paths.len() > 16
            || producer.executable_sha256.len() > 16
            || producer
                .executable_paths
                .iter()
                .any(|path| path.as_os_str().is_empty())
            || producer
                .executable_sha256
                .iter()
                .any(|hash| {
                    hash.len() != 64
                        || !hash.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
        {
            return Err(ConfigError::InvalidLocalIngest);
        }
    }

    Ok(())
}

fn require_peer_constraints(
    producers: &[LocalProducerConfig],
) -> Result<(), ConfigError> {
    if producers
        .iter()
        .any(|producer| {
            producer.expected_uid.is_none()
                && producer.executable_paths.is_empty()
                && producer.executable_sha256.is_empty()
        })
    {
        return Err(ConfigError::InvalidLocalIngest);
    }
    Ok(())
}

impl ControlPlaneConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        validate_https_url("policy_url", &self.policy_url)?;
        validate_https_url("health_url", &self.health_url)?;
        validate_https_url("events_url", &self.events_url)?;

        if self.connect_timeout_ms == 0 || self.request_timeout_ms == 0 {
            return Err(ConfigError::InvalidTimeout);
        }
        Ok(())
    }
}

fn validate_https_url(
    field: &'static str,
    value: &str,
) -> Result<(), ConfigError> {
    let url = Url::parse(value).map_err(|_| ConfigError::InvalidUrl(field))?;
    if url.scheme() != "https" {
        return Err(ConfigError::InsecureUrl(field));
    }
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return Err(ConfigError::UnsafeUrl(field));
    }
    Ok(())
}

fn default_connect_timeout_ms() -> u64 {
    DEFAULT_CONNECT_TIMEOUT_MS
}
fn default_request_timeout_ms() -> u64 {
    DEFAULT_REQUEST_TIMEOUT_MS
}
fn default_spool_max_bytes() -> u64 {
    DEFAULT_SPOOL_MAX_BYTES
}
fn default_segment_max_bytes() -> u64 {
    DEFAULT_SEGMENT_MAX_BYTES
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> RuntimeConfig {
        RuntimeConfig {
            control_plane: ControlPlaneConfig {
                policy_url: "https://control.example/policy".into(),
                health_url: "https://control.example/health".into(),
                events_url: "https://control.example/events".into(),
                bearer_token_file: "token".into(),
                connect_timeout_ms: 5_000,
                request_timeout_ms: 30_000,
            },
            spool_dir: "spool".into(),
            policy_signed_path: "policy.signed.json".into(),
            policy_watermark_path: "policy.version".into(),
            policy_public_key_file: "policy-public-key.b64".into(),
            event_source_path: "events.jsonl".into(),
            event_offset_path: "events.offset".into(),
            health_source_path: "health.json".into(),
            local_ingest_port: None,
            local_ingest_socket_path: None,
            local_ingest_pipe_name: None,
            local_ingest_token_file: None,
            local_ingest_producers: vec![],
            cycle_interval_ms: 1000,
            spool_max_bytes: 1024,
            segment_max_bytes: 256,
        }
    }

    #[test]
    fn requires_https() {
        let mut cfg = config();
        cfg.control_plane.policy_url = "http://control.example/policy".into();
        assert_eq!(
            cfg.validate(),
            Err(ConfigError::InsecureUrl("policy_url"))
        );
    }

    #[test]
    fn rejects_embedded_credentials() {
        let mut cfg = config();
        cfg.control_plane.events_url = "https://user:pass@control.example/events".into();
        assert_eq!(
            cfg.validate(),
            Err(ConfigError::UnsafeUrl("events_url"))
        );
    }

    #[test]
    fn validates_local_ingest_pairing() {
        let mut cfg = config();
        cfg.local_ingest_port = Some(8765);
        assert_eq!(cfg.validate(), Err(ConfigError::InvalidLocalIngest));

        cfg.local_ingest_token_file = Some("local-token".into());
        assert!(cfg.validate().is_ok());

        cfg.local_ingest_port = Some(80);
        assert_eq!(cfg.validate(), Err(ConfigError::InvalidLocalIngest));
    }

    #[test]
    fn validates_bound_local_producers() {
        let mut cfg = config();
        cfg.local_ingest_port = Some(8765);
        cfg.local_ingest_producers = vec![
            LocalProducerConfig {
                agent_id: "agent-a".into(),
                token_file: "agent-a.token".into(),
                expected_uid: Some(1000),
                executable_paths: vec!["/usr/local/bin/agent-a".into()],
            executable_sha256: vec![],
            },
            LocalProducerConfig {
                agent_id: "agent-b".into(),
                token_file: "agent-b.token".into(),
                expected_uid: None,
                executable_paths: vec![],
            executable_sha256: vec![],
            },
        ];
        assert!(cfg.validate().is_ok());

        cfg.local_ingest_producers[1].agent_id = "agent-a".into();
        assert_eq!(cfg.validate(), Err(ConfigError::InvalidLocalIngest));
    }

    #[test]
    fn validates_attested_unix_socket_mode() {
        let mut cfg = config();
        cfg.local_ingest_socket_path = Some("/run/votal/nexus/agent-actions.sock".into());
        cfg.local_ingest_producers = vec![LocalProducerConfig {
            agent_id: "agent-a".into(),
            token_file: "agent-a.token".into(),
            expected_uid: Some(1000),
            executable_paths: vec!["/usr/local/bin/agent-a".into()],
        executable_sha256: vec![],
        }];
        assert!(cfg.validate().is_ok());

        cfg.local_ingest_port = Some(8765);
        assert_eq!(cfg.validate(), Err(ConfigError::InvalidLocalIngest));
    }

    #[test]
    fn attested_transport_requires_peer_constraint() {
        let mut cfg = config();
        cfg.local_ingest_socket_path = Some("/run/votal/nexus/agent-actions.sock".into());
        cfg.local_ingest_producers = vec![LocalProducerConfig {
            agent_id: "agent-a".into(),
            token_file: "agent-a.token".into(),
            expected_uid: None,
            executable_paths: vec![],
        executable_sha256: vec![],
        }];
        assert_eq!(cfg.validate(), Err(ConfigError::InvalidLocalIngest));
    }

    #[test]
    fn validates_windows_named_pipe_mode() {
        let mut cfg = config();
        cfg.local_ingest_pipe_name = Some("VotalNexusAgentActions".into());
        cfg.local_ingest_producers = vec![LocalProducerConfig {
            agent_id: "agent-a".into(),
            token_file: "agent-a.token".into(),
            expected_uid: None,
            executable_paths: vec![r"C:\Program Files\Agent\agent.exe".into()],
        executable_sha256: vec![],
        }];
        assert!(cfg.validate().is_ok());

        cfg.local_ingest_port = Some(8765);
        assert_eq!(cfg.validate(), Err(ConfigError::InvalidLocalIngest));
    }

    #[test]
    fn rejects_invalid_executable_hash_pin() {
        let mut cfg = config();
        cfg.local_ingest_pipe_name = Some("VotalNexusAgentActions".into());
        cfg.local_ingest_producers = vec![LocalProducerConfig {
            agent_id: "agent-a".into(),
            token_file: "agent-a.token".into(),
            expected_uid: None,
            executable_paths: vec![],
            executable_sha256: vec!["not-a-sha256".into()],
        }];
        assert_eq!(cfg.validate(), Err(ConfigError::InvalidLocalIngest));
    }

    #[test]
    fn validates_spool_bounds() {
        let mut cfg = config();
        cfg.segment_max_bytes = 2048;
        assert_eq!(cfg.validate(), Err(ConfigError::InvalidSpoolLimits));
    }
}

fn default_cycle_interval_ms() -> u64 {
    DEFAULT_CYCLE_INTERVAL_MS
}
