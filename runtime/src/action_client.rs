use nexus_agent_core::{AgentActionDecision, AgentActionEvent};
use std::{
    io::{BufReader, Read, Write},
    net::TcpStream,
    path::PathBuf,
};

#[cfg(unix)]
use std::os::unix::net::UnixStream;

const MAX_RESPONSE_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub enum LocalAuthorizationTarget {
    Tcp(u16),
    #[cfg(unix)]
    Unix(PathBuf),
    #[cfg(windows)]
    WindowsPipe(String),
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
