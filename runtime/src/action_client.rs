use crate::credentials::read_secret_file;
use nexus_agent_core::{
    AgentActionDecision, AgentActionEvent, AgentActionKind,
};
use std::sync::atomic::{AtomicU64, Ordering};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use std::{
    io::{BufReader, Read, Write},
    net::TcpStream,
    path::Path,
};

#[cfg(unix)]
use std::{os::unix::net::UnixStream, path::PathBuf};

const MAX_RESPONSE_BYTES: usize = 64 * 1024;
static CLIENT_EVENT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone)]
pub enum LocalAuthorizationTarget {
    Tcp(u16),
    #[cfg(unix)]
    Unix(PathBuf),
    #[cfg(windows)]
    WindowsPipe(String),
}

#[derive(Debug, Clone)]
pub struct AgentActionClient {
    target: LocalAuthorizationTarget,
    token: String,
    device_id: String,
}

impl AgentActionClient {
    pub fn from_token_file(
        target: LocalAuthorizationTarget,
        device_id: impl Into<String>,
        token_file: &Path,
    ) -> Result<Self, String> {
        let device_id = device_id.into();
        if device_id.is_empty() || device_id.len() > 256 {
            return Err("device_id must be between 1 and 256 bytes".to_string());
        }

        let token = read_secret_file(token_file, 32, 512, true)
            .map_err(|error| format!("invalid local authorization token: {error:?}"))?;

        Ok(Self {
            target,
            token,
            device_id,
        })
    }

    pub fn authorize(&self, event: &AgentActionEvent) -> Result<AgentActionDecision, String> {
        authorize_action(&self.target, &self.token, event)
    }

    pub fn authorize_mcp_tool(
        &self,
        server_id: &str,
        tool_name: &str,
        session_id: Option<&str>,
        risk_tags: &[String],
    ) -> Result<AgentActionDecision, String> {
        let event = self.mcp_event(
            AgentActionKind::McpToolCall,
            server_id,
            Some(tool_name),
            "call",
            None,
            session_id,
            risk_tags,
        )?;
        self.authorize(&event)
    }

    pub fn authorize_mcp_resource_read(
        &self,
        server_id: &str,
        resource_uri: &str,
        session_id: Option<&str>,
        risk_tags: &[String],
    ) -> Result<AgentActionDecision, String> {
        let event = self.mcp_event(
            AgentActionKind::McpResourceRead,
            server_id,
            None,
            "read",
            Some(resource_uri),
            session_id,
            risk_tags,
        )?;
        self.authorize(&event)
    }

    fn mcp_event(
        &self,
        kind: AgentActionKind,
        server_id: &str,
        tool_name: Option<&str>,
        operation: &str,
        resource: Option<&str>,
        session_id: Option<&str>,
        risk_tags: &[String],
    ) -> Result<AgentActionEvent, String> {
        if server_id.is_empty() || server_id.len() > 256 {
            return Err("server_id must be between 1 and 256 bytes".to_string());
        }
        if tool_name.is_some_and(|value| value.is_empty() || value.len() > 256) {
            return Err("tool_name must be between 1 and 256 bytes".to_string());
        }
        if session_id.is_some_and(|value| value.is_empty() || value.len() > 256) {
            return Err("session_id must be between 1 and 256 bytes".to_string());
        }

        let now = OffsetDateTime::now_utc();
        let timestamp = now
            .format(&Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string());
        let sequence = CLIENT_EVENT_SEQUENCE.fetch_add(1, Ordering::Relaxed) + 1;

        let event = AgentActionEvent {
            event_id: format!("agent-sdk-{}-{sequence}", std::process::id()),
            timestamp,
            device_id: self.device_id.clone(),
            pid: Some(std::process::id()),
            // The bridge binds authoritative agent identity from the producer
            // credential. SDK callers do not self-assert agent_id here.
            agent_id: None,
            session_id: session_id.map(str::to_string),
            kind,
            mcp_server: Some(server_id.to_string()),
            tool_name: tool_name.map(str::to_string),
            operation: operation.to_string(),
            resource: resource.map(str::to_string),
            risk_tags: risk_tags.to_vec(),
        };

        event
            .validate()
            .map_err(|error| format!("constructed agent action is invalid: {error}"))?;
        Ok(event)
    }
}

pub fn authorize_action(
    target: &LocalAuthorizationTarget,
    token: &str,
    event: &AgentActionEvent,
) -> Result<AgentActionDecision, String> {
    event
        .validate()
        .map_err(|error| format!("invalid agent action: {error}"))?;
    let body = serde_json::to_vec(event)
        .map_err(|error| format!("cannot encode agent action: {error}"))?;

    let response = match target {
        LocalAuthorizationTarget::Tcp(port) => {
            let mut stream = TcpStream::connect(("127.0.0.1", *port))
                .map_err(|error| format!("TCP connect failed: {error}"))?;
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(3)))
                .map_err(|error| error.to_string())?;
            stream
                .set_write_timeout(Some(std::time::Duration::from_secs(3)))
                .map_err(|error| error.to_string())?;
            exchange(&mut stream, token, &body)?
        }
        #[cfg(unix)]
        LocalAuthorizationTarget::Unix(path) => {
            let mut stream = UnixStream::connect(path)
                .map_err(|error| format!("Unix connect failed: {error}"))?;
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(3)))
                .map_err(|error| error.to_string())?;
            stream
                .set_write_timeout(Some(std::time::Duration::from_secs(3)))
                .map_err(|error| error.to_string())?;
            exchange(&mut stream, token, &body)?
        }
        #[cfg(windows)]
        LocalAuthorizationTarget::WindowsPipe(name) => {
            let full_name = if name.starts_with(r"\\.\pipe\") {
                name.clone()
            } else {
                format!(r"\\.\pipe\{name}")
            };
            let mut pipe = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&full_name)
                .map_err(|error| format!("named-pipe connect failed: {error}"))?;
            exchange(&mut pipe, token, &body)?
        }
    };

    parse_decision_response(&response)
}

fn exchange<S: Read + Write>(
    stream: &mut S,
    token: &str,
    body: &[u8],
) -> Result<Vec<u8>, String> {
    write!(
        stream,
        "POST /v1/agent-actions HTTP/1.1\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .map_err(|error| format!("request write failed: {error}"))?;
    stream
        .write_all(body)
        .map_err(|error| format!("request body write failed: {error}"))?;
    stream
        .flush()
        .map_err(|error| format!("request flush failed: {error}"))?;

    let mut response = Vec::new();
    BufReader::new(stream)
        .take((MAX_RESPONSE_BYTES + 1) as u64)
        .read_to_end(&mut response)
        .map_err(|error| format!("response read failed: {error}"))?;
    if response.len() > MAX_RESPONSE_BYTES {
        return Err("authorization response too large".to_string());
    }
    Ok(response)
}

fn parse_decision_response(response: &[u8]) -> Result<AgentActionDecision, String> {
    let marker = b"\r\n\r\n";
    let body_start = response
        .windows(marker.len())
        .position(|window| window == marker)
        .map(|offset| offset + marker.len())
        .ok_or_else(|| "invalid HTTP response".to_string())?;

    let header = std::str::from_utf8(&response[..body_start])
        .map_err(|_| "non-UTF8 response header".to_string())?;
    let status = header
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| "missing HTTP status".to_string())?;

    if status != 200 && status != 403 {
        let body = String::from_utf8_lossy(&response[body_start..]);
        return Err(format!(
            "authorization bridge returned HTTP {status}: {body}"
        ));
    }

    serde_json::from_slice(&response[body_start..])
        .map_err(|error| format!("invalid decision response: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_agent_core::DecisionAction;

    #[test]
    fn sdk_event_builder_does_not_self_assert_agent_identity() {
        let client = AgentActionClient {
            target: LocalAuthorizationTarget::Tcp(8765),
            token: "x".repeat(32),
            device_id: "device-1".into(),
        };
        let event = client
            .mcp_event(
                AgentActionKind::McpToolCall,
                "filesystem",
                Some("write_file"),
                "call",
                None,
                Some("session-1"),
                &["filesystem_write".into()],
            )
            .unwrap();

        assert!(event.agent_id.is_none());
        assert_eq!(event.pid, Some(std::process::id()));
        assert_eq!(event.tool_name.as_deref(), Some("write_file"));
        assert_eq!(event.risk_tags, vec!["filesystem_write"]);
    }

    #[test]
    fn sdk_event_builder_rejects_empty_server_id() {
        let client = AgentActionClient {
            target: LocalAuthorizationTarget::Tcp(8765),
            token: "x".repeat(32),
            device_id: "device-1".into(),
        };
        assert!(client
            .mcp_event(
                AgentActionKind::McpToolCall,
                "",
                Some("tool"),
                "call",
                None,
                None,
                &[],
            )
            .is_err());
    }

    #[test]
    fn parses_allow_response() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"action\":\"allow\",\"rule_id\":null,\"reason\":\"test\",\"policy_version\":1,\"would_deny\":false}";
        let decision = parse_decision_response(response).unwrap();
        assert_eq!(decision.action, DecisionAction::Allow);
        assert_eq!(decision.policy_version, 1);
    }

    #[test]
    fn parses_deny_response() {
        let response = b"HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\n\r\n{\"action\":\"deny\",\"rule_id\":\"deny-1\",\"reason\":\"test\",\"policy_version\":2,\"would_deny\":true}";
        let decision = parse_decision_response(response).unwrap();
        assert_eq!(decision.action, DecisionAction::Deny);
        assert!(decision.would_deny);
    }
}
