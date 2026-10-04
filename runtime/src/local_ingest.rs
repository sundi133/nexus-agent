use nexus_agent_core::{
    AgentActionDecision, AgentActionEvent, DecisionAction, PolicyBundle,
};
use serde::Serialize;
use std::{
    io::{self, BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        mpsc::Sender,
        Arc, RwLock,
    },
    thread,
    time::Duration,
};

const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_BODY_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Serialize)]
pub struct AgentActionAuditRecord {
    pub event: AgentActionEvent,
    pub decision: AgentActionDecision,
}

pub fn spawn_local_ingest(
    port: u16,
    token: String,
    policy: Arc<RwLock<Option<PolicyBundle>>>,
    sender: Sender<AgentActionAuditRecord>,
) -> io::Result<thread::JoinHandle<()>> {
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    listener.set_nonblocking(true)?;

    Ok(thread::spawn(move || loop {
        match listener.accept() {
            Ok((stream, _)) => {
                let _ = handle_connection(stream, &token, &policy, &sender);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(25));
            }
            Err(_) => {
                thread::sleep(Duration::from_millis(100));
            }
        }
    }))
}

fn handle_connection(
    mut stream: TcpStream,
    token: &str,
    policy: &Arc<RwLock<Option<PolicyBundle>>>,
    sender: &Sender<AgentActionAuditRecord>,
) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;

    let cloned = stream.try_clone()?;
    let mut reader = BufReader::new(cloned);

    let mut request_line = String::new();
    if reader.read_line(&mut request_line)? == 0 {
        return Ok(());
    }
    if request_line.len() > 4096 {
        return write_error_response(&mut stream, 400, "request line too large");
    }

    let mut header_bytes = request_line.len();
    let mut authorization = None;
    let mut content_length = None;

    loop {
        let mut line = String::new();
        let read = reader.read_line(&mut line)?;
        if read == 0 {
            return write_error_response(&mut stream, 400, "incomplete headers");
        }
        header_bytes = header_bytes.saturating_add(read);
        if header_bytes > MAX_HEADER_BYTES {
            return write_error_response(&mut stream, 431, "headers too large");
        }

        if line == "
" || line == "
" {
            break;
        }

        if let Some((name, value)) = line.split_once(':') {
            match name.trim().to_ascii_lowercase().as_str() {
                "authorization" => authorization = Some(value.trim().to_string()),
                "content-length" => {
                    content_length = value.trim().parse::<usize>().ok();
                }
                _ => {}
            }
        }
    }

    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or_default();

    if method != "POST" || path != "/v1/agent-actions" {
        return write_error_response(&mut stream, 404, "not found");
    }

    let supplied_token = authorization
        .as_deref()
        .and_then(|value| value.strip_prefix("Bearer "));
    if !supplied_token.is_some_and(|supplied| {
        constant_time_eq(supplied.as_bytes(), token.as_bytes())
    }) {
        return write_error_response(&mut stream, 401, "unauthorized");
    }

    let Some(body_len) = content_length else {
        return write_error_response(&mut stream, 411, "content-length required");
    };
    if body_len == 0 || body_len > MAX_BODY_BYTES {
        return write_error_response(&mut stream, 413, "invalid body size");
    }

    let mut body = vec![0u8; body_len];
    reader.read_exact(&mut body)?;

    let event: AgentActionEvent = match serde_json::from_slice(&body) {
        Ok(event) => event,
        Err(_) => return write_error_response(&mut stream, 400, "invalid JSON"),
    };
    if event.validate().is_err() {
        return write_error_response(&mut stream, 422, "invalid agent action");
    }

    let decision = decide_agent_action(policy, &event);
    let audit = AgentActionAuditRecord {
        event,
        decision: decision.clone(),
    };

    if sender.send(audit).is_err() && decision.action != DecisionAction::Deny {
        return write_error_response(&mut stream, 503, "runtime unavailable");
    }

    let status = if decision.action == DecisionAction::Deny {
        403
    } else {
        200
    };
    write_decision_response(&mut stream, status, &decision)
}

fn decide_agent_action(
    policy: &Arc<RwLock<Option<PolicyBundle>>>,
    event: &AgentActionEvent,
) -> AgentActionDecision {
    let Ok(guard) = policy.read() else {
        return fail_open_decision("policy lock unavailable");
    };
    guard
        .as_ref()
        .map(|policy| policy.evaluate_agent_action(event))
        .unwrap_or_else(|| fail_open_decision("no verified policy loaded"))
}

fn fail_open_decision(reason: &str) -> AgentActionDecision {
    AgentActionDecision {
        action: DecisionAction::Allow,
        rule_id: None,
        reason: reason.to_string(),
        policy_version: 0,
        would_deny: false,
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        difference |= a ^ b;
    }
    difference == 0
}

fn write_decision_response(
    stream: &mut TcpStream,
    status: u16,
    decision: &AgentActionDecision,
) -> io::Result<()> {
    let reason = if status == 403 { "Forbidden" } else { "OK" };
    let body = serde_json::to_string(decision)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    write!(
        stream,
        "HTTP/1.1 {status} {reason}
Content-Type: application/json
Content-Length: {}
Connection: close

{}",
        body.len(),
        body
    )?;
    stream.flush()
}

fn write_error_response(stream: &mut TcpStream, status: u16, message: &str) -> io::Result<()> {
    let reason = match status {
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        411 => "Length Required",
        413 => "Payload Too Large",
        422 => "Unprocessable Entity",
        431 => "Request Header Fields Too Large",
        503 => "Service Unavailable",
        _ => "Error",
    };

    let body = serde_json::json!({
        "status": status,
        "message": message,
    })
    .to_string();
    write!(
        stream,
        "HTTP/1.1 {status} {reason}
Content-Type: application/json
Content-Length: {}
Connection: close

{}",
        body.len(),
        body
    )?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_agent_core::{
        AgentActionKind, AgentActionRule, EnforcementMode,
    };
    use std::sync::mpsc;

    fn event() -> AgentActionEvent {
        AgentActionEvent {
            event_id: "a-1".into(),
            timestamp: "2026-10-04T00:00:00Z".into(),
            device_id: "device-1".into(),
            pid: Some(42),
            agent_id: Some("agent-1".into()),
            session_id: Some("session-1".into()),
            kind: AgentActionKind::McpToolCall,
            mcp_server: Some("filesystem".into()),
            tool_name: Some("write_file".into()),
            operation: "write".into(),
            resource: Some("/etc/hosts".into()),
            risk_tags: vec!["filesystem_write".into()],
        }
    }

    fn deny_policy(mode: EnforcementMode) -> PolicyBundle {
        PolicyBundle {
            version: 7,
            mode,
            rules: vec![],
            agent_action_rules: vec![AgentActionRule {
                id: "deny-etc-write".into(),
                action: DecisionAction::Deny,
                kinds: vec![AgentActionKind::McpToolCall],
                mcp_servers: vec!["filesystem".into()],
                tool_names: vec!["write_file".into()],
                operations: vec!["write".into()],
                resource_prefixes: vec!["/etc/".into()],
                risk_tags: vec![],
            }],
            ransomware_response: None,
        }
    }

    #[test]
    fn token_comparison_requires_exact_value() {
        assert!(constant_time_eq(b"abcdef", b"abcdef"));
        assert!(!constant_time_eq(b"abcdef", b"abcdeg"));
        assert!(!constant_time_eq(b"abcdef", b"abc"));
    }

    #[test]
    fn validates_expected_agent_action_payload() {
        assert!(event().validate().is_ok());
    }

    #[test]
    fn channel_accepts_valid_audit_record() {
        let (tx, rx) = mpsc::channel();
        let policy = Arc::new(RwLock::new(Some(deny_policy(EnforcementMode::Audit))));
        let event = event();
        let decision = decide_agent_action(&policy, &event);
        tx.send(AgentActionAuditRecord {
            event,
            decision,
        })
        .unwrap();
        let record = rx.recv().unwrap();
        assert_eq!(record.decision.action, DecisionAction::Alert);
        assert!(record.decision.would_deny);
    }

    #[test]
    fn enforce_policy_denies_matching_tool_action() {
        let policy = Arc::new(RwLock::new(Some(deny_policy(EnforcementMode::Enforce))));
        let decision = decide_agent_action(&policy, &event());
        assert_eq!(decision.action, DecisionAction::Deny);
        assert_eq!(decision.rule_id.as_deref(), Some("deny-etc-write"));
    }

    #[test]
    fn missing_policy_fails_open() {
        let policy = Arc::new(RwLock::new(None));
        let decision = decide_agent_action(&policy, &event());
        assert_eq!(decision.action, DecisionAction::Allow);
        assert_eq!(decision.policy_version, 0);
    }
}
