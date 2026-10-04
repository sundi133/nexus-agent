use crate::config::ControlPlaneConfig;
use nexus_agent_core::AgentHealth;
use reqwest::{
    blocking::{Client, Response},
    header::{ETAG, IF_NONE_MATCH},
    StatusCode,
};
use std::{
    fs,
    io::{self, Read},
    time::Duration,
};
use thiserror::Error;

const MAX_POLICY_BYTES: u64 = 1024 * 1024;
const MAX_RESPONSE_BODY_BYTES: u64 = 64 * 1024;

#[derive(Debug)]
pub enum PolicyFetch {
    NotModified,
    Updated {
        body: Vec<u8>,
        etag: Option<String>,
    },
}

pub trait ControlPlaneTransport {
    fn fetch_policy(
        &self,
        previous_etag: Option<&str>,
    ) -> Result<PolicyFetch, TransportError>;

    fn post_health(&self, health: &AgentHealth) -> Result<(), TransportError>;
    fn post_events(&self, jsonl: &[u8]) -> Result<(), TransportError>;
}

#[derive(Debug)]
pub struct HttpControlPlane {
    config: ControlPlaneConfig,
    client: Client,
}

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("transport configuration is invalid: {0}")]
    Config(String),
    #[error("credential file is invalid")]
    Credential,
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("control plane returned HTTP {0}")]
    Status(StatusCode),
    #[error("response body is too large")]
    TooLarge,
    #[error("response I/O failed: {0}")]
    Io(#[from] io::Error),
}

impl HttpControlPlane {
    pub fn new(config: ControlPlaneConfig) -> Result<Self, TransportError> {
        config
            .validate()
            .map_err(|error| TransportError::Config(error.to_string()))?;

        let client = Client::builder()
            .connect_timeout(Duration::from_millis(config.connect_timeout_ms))
            .timeout(Duration::from_millis(config.request_timeout_ms))
            .user_agent("Votal-Nexus-Agent/0.1")
            .build()?;

        Ok(Self { config, client })
    }

    fn fetch_policy_impl(
        &self,
        previous_etag: Option<&str>,
    ) -> Result<PolicyFetch, TransportError> {
        let token = self.read_token()?;
        let mut request = self
            .client
            .get(&self.config.policy_url)
            .bearer_auth(token);

        if let Some(etag) = previous_etag {
            request = request.header(IF_NONE_MATCH, etag);
        }

        let response = request.send()?;
        if response.status() == StatusCode::NOT_MODIFIED {
            return Ok(PolicyFetch::NotModified);
        }
        ensure_success(&response)?;

        let etag = response
            .headers()
            .get(ETAG)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let body = read_bounded(response, MAX_POLICY_BYTES)?;

        Ok(PolicyFetch::Updated { body, etag })
    }

    fn post_health_impl(&self, health: &AgentHealth) -> Result<(), TransportError> {
        let token = self.read_token()?;
        let response = self
            .client
            .post(&self.config.health_url)
            .bearer_auth(token)
            .json(health)
            .send()?;
        ensure_success(&response)
    }

    fn post_events_impl(&self, jsonl: &[u8]) -> Result<(), TransportError> {
        let token = self.read_token()?;
        let response = self
            .client
            .post(&self.config.events_url)
            .bearer_auth(token)
            .header("content-type", "application/x-ndjson")
            .body(jsonl.to_vec())
            .send()?;
        ensure_success(&response)
    }

    fn read_token(&self) -> Result<String, TransportError> {
        let token = fs::read_to_string(&self.config.bearer_token_file)
            .map_err(|_| TransportError::Credential)?;
        let token = token.trim();
        if token.is_empty() || token.len() > 16 * 1024 {
            return Err(TransportError::Credential);
        }
        Ok(token.to_string())
    }
}

fn ensure_success(response: &Response) -> Result<(), TransportError> {
    if response.status().is_success() {
        Ok(())
    } else {
        Err(TransportError::Status(response.status()))
    }
}

fn read_bounded(
    response: Response,
    max_bytes: u64,
) -> Result<Vec<u8>, TransportError> {
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes)
    {
        return Err(TransportError::TooLarge);
    }

    let mut limited = response.take(max_bytes + 1);
    let mut body = Vec::new();
    limited.read_to_end(&mut body)?;
    if body.len() as u64 > max_bytes {
        return Err(TransportError::TooLarge);
    }
    Ok(body)
}


impl ControlPlaneTransport for HttpControlPlane {
    fn fetch_policy(
        &self,
        previous_etag: Option<&str>,
    ) -> Result<PolicyFetch, TransportError> {
        self.fetch_policy_impl(previous_etag)
    }

    fn post_health(&self, health: &AgentHealth) -> Result<(), TransportError> {
        self.post_health_impl(health)
    }

    fn post_events(&self, jsonl: &[u8]) -> Result<(), TransportError> {
        self.post_events_impl(jsonl)
    }
}
