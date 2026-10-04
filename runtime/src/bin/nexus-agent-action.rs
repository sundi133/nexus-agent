use nexus_agent_core::{AgentActionDecision, AgentActionEvent, DecisionAction};
use nexus_agent_runtime::read_secret_file;
use std::{
    env,
    fs,
    io::{self, BufRead, BufReader, Read, Write},
    net::TcpStream,
    path::PathBuf,
    process,
};

#[cfg(unix)]
use std::os::unix::net::UnixStream;

const MAX_RESPONSE_BYTES: usize = 64 * 1024;

enum Transport {
    Tcp(u16),
    #[cfg(unix)]
    Unix(PathBuf),
    #[cfg(windows)]
    Pipe(String),
}

fn usage() -> ! {
    eprintln!(
        "usage: nexus-agent-action --event <event.json> --token-file <token> \
         (--tcp <port> | --unix <socket-path> | --pipe <name>)"
    );
    process::exit(2);
}

fn main() {
    match run() {
        Ok(decision) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&decision).expect("decision serializes")
            );
            match decision.action {
                DecisionAction::Allow => {}
                DecisionAction::Alert => process::exit(10),
                DecisionAction::Deny => process::exit(20),
            }
        }
        Err(error) => {
            eprintln!("nexus-agent-action: {error}");
            process::exit(1);
        }
    }
}

fn run() -> Result<AgentActionDecision, String> {
    let args: Vec<String> = env::args().skip(1).collect();
    let mut event_path = None;
    let mut token_path = None;
    let mut transport = None;
    let mut index = 0usize;

    while index < args.len() {
        let value = args.get(index).map(String::as_str).unwrap_or_default();
        match value {
            "--event" => {
                index += 1;
                event_path = args.get(index).map(PathBuf::from);
            }
            "--token-file" => {
                index += 1;
                token_path = args.get(index).map(PathBuf::from);
            }
            "--tcp" => {
                index += 1;
                let port = args
                    .get(index)
                    .and_then(|value| value.parse::<u16>().ok())
                    .filter(|port| *port >= 1024)
                    .ok_or_else(|| "invalid --tcp port".to_string())?;
                set_transport(&mut transport, Transport::Tcp(port))?;
            }
            #[cfg(unix)]
            "--unix" => {
                index += 1;
                let path = args
                    .get(index)
                    .map(PathBuf::from)
                    .ok_or_else(|| "missing --unix path".to_string())?;
                set_transport(&mut transport, Transport::Unix(path))?;
            }
            #[cfg(windows)]
            "--pipe" => {
                index += 1;
                let name = args
                    .get(index)
                    .cloned()
                    .filter(|value| !value.trim().is_empty())
                    .ok_or_else(|| "missing --pipe name".to_string())?;
                set_transport(&mut transport, Transport::Pipe(name))?;
            }
            _ => return Err(format!("unknown argument: {value}")),
        }
        index += 1;
    }

    let event_path = event_path.ok_or_else(|| "missing --event".to_string())?;
    let token_path = token_path.ok_or_else(|| "missing --token-file".to_string())?;
    let transport = transport.ok_or_else(|| "missing transport selector".to_string())?;

    let event_bytes =
        fs::read(&event_path).map_err(|error| format!("cannot read event: {error}"))?;
    let event: AgentActionEvent = serde_json::from_slice(&event_bytes)
        .map_err(|error| format!("invalid event JSON: {error}"))?;
    event
        .validate()
        .map_err(|error| format!("invalid agent action: {error}"))?;

    let token = read_secret_file(&token_path, 32, 512, true)
        .map_err(|error| format!("invalid token file: {error:?}"))?;
    let body = serde_json::to_vec(&event)
        .map_err(|error| format!("cannot encode event: {error}"))?;

    let response = match transport {
        Transport::Tcp(port) => {
            let mut stream = TcpStream::connect(("127.0.0.1", port))
                .map_err(|error| format!("TCP connect failed: {error}"))?;
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(3)))
                .map_err(|error| error.to_string())?;
            stream
                .set_write_timeout(Some(std::time::Duration::from_secs(3)))
                .map_err(|error| error.to_string())?;
            exchange(&mut stream, &token, &body)?
        }
        #[cfg(unix)]
        Transport::Unix(path) => {
            let mut stream =
                UnixStream::connect(path).map_err(|error| format!("Unix connect failed: {error}"))?;
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(3)))
                .map_err(|error| error.to_string())?;
            stream
                .set_write_timeout(Some(std::time::Duration::from_secs(3)))
                .map_err(|error| error.to_string())?;
            exchange(&mut stream, &token, &body)?
        }
        #[cfg(windows)]
        Transport::Pipe(name) => {
            let full_name = if name.starts_with(r"\\.\pipe\") {
                name
            } else {
                format!(r"\\.\pipe\{name}")
            };
            let mut pipe = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&full_name)
                .map_err(|error| format!("named-pipe connect failed: {error}"))?;
            exchange(&mut pipe, &token, &body)?
        }
    };

    parse_decision_response(&response)
}

fn set_transport(
    slot: &mut Option<Transport>,
    value: Transport,
) -> Result<(), String> {
    if slot.is_some() {
        return Err("select exactly one local transport".to_string());
    }
    *slot = Some(value);
    Ok(())
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

    let mut reader = BufReader::new(stream);
    let mut response = Vec::new();
    reader
        .by_ref()
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
        return Err(format!("authorization bridge returned HTTP {status}: {body}"));
    }

    serde_json::from_slice(&response[body_start..])
        .map_err(|error| format!("invalid decision response: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

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
