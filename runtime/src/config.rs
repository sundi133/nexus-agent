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
    #[serde(default = "default_cycle_interval_ms")]
    pub cycle_interval_ms: u64,
    #[serde(default = "default_spool_max_bytes")]
    pub spool_max_bytes: u64,
    #[serde(default = "default_segment_max_bytes")]
    pub segment_max_bytes: u64,
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
        Ok(())
    }
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
    fn validates_spool_bounds() {
        let mut cfg = config();
        cfg.segment_max_bytes = 2048;
        assert_eq!(cfg.validate(), Err(ConfigError::InvalidSpoolLimits));
    }
}

fn default_cycle_interval_ms() -> u64 {
    DEFAULT_CYCLE_INTERVAL_MS
}
