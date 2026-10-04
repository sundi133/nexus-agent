use nexus_agent_core::AgentActionEvent;
use std::{
    io::{self, BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    sync::mpsc::Sender,
    thread,
    time::Duration,
};

const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_BODY_BYTES: usize = 64 * 1024;

pub fn spawn_local_ingest(
    port: u16,
    token: String,
    sender: Sender<AgentActionEvent>,
) -> io::Result<thread::JoinHandle<()>> {
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    listener.set_nonblocking(true)?;

    Ok(thread::spawn(move || loop {
        match listener.accept() {
            Ok((stream, _)) => {
                let _ = handle_connection(stream, &token, &sender);
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
    sender: &Sender<AgentActionEvent>,
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
        return write_response(&mut stream, 400, "request line too large");
    }

    let mut header_bytes = request_line.len();
    let mut authorization = None;
    let mut content_length = None;

    loop {
        let mut line = String::new();
        let read = reader.read_line(&mut line)?;
        if read == 0 {
            return write_response(&mut stream, 400, "incomplete headers");
        }
        header_bytes = header_bytes.saturating_add(read);
        if header_bytes > MAX_HEADER_BYTES {
            return write_response(&mut stream, 431, "headers too large");
        }

        if line == "\r\n" || line == "\n" {
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
        return write_response(&mut stream, 404, "not found");
    }

    let expected = format!("Bearer {token}");
    if authorization.as_deref() != Some(expected.as_str()) {
        return write_response(&mut stream, 401, "unauthorized");
    }

    let Some(body_len) = content_length else {
        return write_response(&mut stream, 411, "content-length required");
    };
    if body_len == 0 || body_len > MAX_BODY_BYTES {
        return write_response(&mut stream, 413, "invalid body size");
    }

    let mut body = vec![0u8; body_len];
    reader.read_exact(&mut body)?;

    let event: AgentActionEvent = match serde_json::from_slice(&body) {
        Ok(event) => event,
        Err(_) => return write_response(&mut stream, 400, "invalid JSON"),
    };
    if event.validate().is_err() {
        return write_response(&mut stream, 422, "invalid agent action");
    }

    if sender.send(event).is_err() {
        return write_response(&mut stream, 503, "runtime unavailable");
    }

    write_response(&mut stream, 202, "accepted")
}

fn write_response(stream: &mut TcpStream, status: u16, message: &str) -> io::Result<()> {
    let reason = match status {
        202 => "Accepted",
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

    let body = format!("{{\"status\":{status},\"message\":\"{message}\"}}\n");
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    fn event_json() -> String {
        serde_json::json!({
            "event_id": "a-1",
            "timestamp": "2026-10-04T00:00:00Z",
            "device_id": "device-1",
            "pid": 42,
            "agent_id": "agent-1",
            "session_id": "session-1",
            "kind": "mcp_tool_call",
            "mcp_server": "filesystem",
            "tool_name": "read_file",
            "operation": "read",
            "resource": "/tmp/demo.txt",
            "risk_tags": ["filesystem_read"]
        })
        .to_string()
    }

    #[test]
    fn validates_expected_agent_action_payload() {
        let event: AgentActionEvent = serde_json::from_str(&event_json()).unwrap();
        assert!(event.validate().is_ok());
    }

    #[test]
    fn channel_accepts_valid_event() {
        let (tx, rx) = mpsc::channel();
        let event: AgentActionEvent = serde_json::from_str(&event_json()).unwrap();
        tx.send(event).unwrap();
        assert_eq!(rx.recv().unwrap().tool_name.as_deref(), Some("read_file"));
    }
}
