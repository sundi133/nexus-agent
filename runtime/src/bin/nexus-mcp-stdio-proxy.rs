use nexus_agent_core::DecisionAction;
use nexus_agent_runtime::{
    authorize_action, normalize_mcp_action, read_secret_file, LocalAuthorizationTarget,
};
use serde_json::Value;
use std::{
    env,
    io::{self, BufRead, BufReader, BufWriter, Write},
    path::PathBuf,
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    thread,
};

const MAX_MCP_FRAME_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnavailableMode {
    Deny,
    Allow,
}

struct Config {
    server_id: String,
    device_id: String,
    token_file: PathBuf,
    target: LocalAuthorizationTarget,
    unavailable_mode: UnavailableMode,
    command: String,
    command_args: Vec<String>,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("nexus-mcp-stdio-proxy: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let config = parse_args()?;
    let token = read_secret_file(&config.token_file, 32, 512, true)
        .map_err(|error| format!("invalid token file: {error:?}"))?;

    let mut child = Command::new(&config.command)
        .args(&config.command_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|error| format!("cannot spawn MCP server: {error}"))?;

    let mut child_stdin = child
        .stdin
        .take()
        .ok_or_else(|| "child stdin unavailable".to_string())?;
    let child_stdout = child
        .stdout
        .take()
        .ok_or_else(|| "child stdout unavailable".to_string())?;

    let stdout = Arc::new(Mutex::new(BufWriter::new(io::stdout())));
    let stdout_for_child = stdout.clone();

    let output_thread = thread::spawn(move || -> Result<(), String> {
        let mut reader = BufReader::new(child_stdout);
        while let Some(frame) = read_frame(&mut reader)
            .map_err(|error| format!("MCP server stdout read failed: {error}"))?
        {
            let mut out = stdout_for_child
                .lock()
                .map_err(|_| "stdout lock poisoned".to_string())?;
            out.write_all(&frame)
                .map_err(|error| format!("stdout write failed: {error}"))?;
            out.flush()
                .map_err(|error| format!("stdout flush failed: {error}"))?;
        }
        Ok(())
    });

    let stdin = io::stdin();
    let mut input = BufReader::new(stdin.lock());

    while let Some(frame) =
        read_frame(&mut input).map_err(|error| format!("host stdin read failed: {error}"))?
    {
        let trimmed = trim_newline(&frame);
        let parsed: Value = match serde_json::from_slice(trimmed) {
            Ok(value) => value,
            Err(_) => {
                // Preserve protocol compatibility: malformed input is still
                // the downstream server's responsibility.
                child_stdin
                    .write_all(&frame)
                    .map_err(|error| format!("child stdin write failed: {error}"))?;
                child_stdin
                    .flush()
                    .map_err(|error| format!("child stdin flush failed: {error}"))?;
                continue;
            }
        };

        let Some(action) = normalize_mcp_action(
            &config.server_id,
            &config.device_id,
            &parsed,
            "mcp-stdio",
        ) else {
            child_stdin
                .write_all(&frame)
                .map_err(|error| format!("child stdin write failed: {error}"))?;
            child_stdin
                .flush()
                .map_err(|error| format!("child stdin flush failed: {error}"))?;
            continue;
        };

        match authorize_action(&config.target, &token, &action) {
            Ok(decision) if decision.action != DecisionAction::Deny => {
                if decision.action == DecisionAction::Alert {
                    eprintln!(
                        "nexus-mcp-stdio-proxy: policy alert method={} rule_id={} policy_version={}",
                        parsed
                            .get("method")
                            .and_then(Value::as_str)
                            .unwrap_or("unknown"),
                        decision.rule_id.as_deref().unwrap_or("none"),
                        decision.policy_version
                    );
                }
                child_stdin
                    .write_all(&frame)
                    .map_err(|error| format!("child stdin write failed: {error}"))?;
                child_stdin
                    .flush()
                    .map_err(|error| format!("child stdin flush failed: {error}"))?;
            }
            Ok(decision) => {
                write_denial(
                    &stdout,
                    parsed.get("id"),
                    -32003,
                    "Nexus policy denied MCP action",
                    serde_json::json!({
                        "rule_id": decision.rule_id,
                        "policy_version": decision.policy_version,
                        "would_deny": decision.would_deny
                    }),
                )?;
            }
            Err(error) if config.unavailable_mode == UnavailableMode::Allow => {
                eprintln!(
                    "nexus-mcp-stdio-proxy: authorization unavailable; fail-open: {error}"
                );
                child_stdin
                    .write_all(&frame)
                    .map_err(|write_error| {
                        format!("child stdin write failed: {write_error}")
                    })?;
                child_stdin
                    .flush()
                    .map_err(|flush_error| {
                        format!("child stdin flush failed: {flush_error}")
                    })?;
            }
            Err(error) => {
                write_denial(
                    &stdout,
                    parsed.get("id"),
                    -32004,
                    "Nexus authorization unavailable",
                    serde_json::json!({"detail": error}),
                )?;
            }
        }
    }

    drop(child_stdin);
    let status = child
        .wait()
        .map_err(|error| format!("cannot wait for MCP server: {error}"))?;

    match output_thread.join() {
        Ok(Ok(())) => {}
        Ok(Err(error)) => return Err(error),
        Err(_) => return Err("MCP server output thread panicked".to_string()),
    }

    if !status.success() {
        return Err(format!("MCP server exited with status {status}"));
    }

    Ok(())
}

fn write_denial(
    stdout: &Arc<Mutex<BufWriter<io::Stdout>>>,
    id: Option<&Value>,
    code: i64,
    message: &str,
    data: Value,
) -> Result<(), String> {
    let Some(id) = id else {
        // MCP tool/resource calls are requests. If a malformed notification
        // arrives without an id, do not forward it and do not fabricate an id.
        eprintln!(
            "nexus-mcp-stdio-proxy: blocked MCP action without JSON-RPC id: {message}"
        );
        return Ok(());
    };

    let response = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message,
            "data": data
        }
    });

    let mut out = stdout
        .lock()
        .map_err(|_| "stdout lock poisoned".to_string())?;
    serde_json::to_writer(&mut *out, &response)
        .map_err(|error| format!("cannot encode denial response: {error}"))?;
    out.write_all(b"\n")
        .map_err(|error| format!("stdout write failed: {error}"))?;
    out.flush()
        .map_err(|error| format!("stdout flush failed: {error}"))
}

fn read_frame<R: BufRead>(reader: &mut R) -> io::Result<Option<Vec<u8>>> {
    let mut frame = Vec::new();

    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return if frame.is_empty() {
                Ok(None)
            } else {
                Ok(Some(frame))
            };
        }

        let newline = available.iter().position(|byte| *byte == b'\n');
        let take = newline.map_or(available.len(), |position| position + 1);

        if frame.len().saturating_add(take) > MAX_MCP_FRAME_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "MCP stdio frame exceeds 4 MiB",
            ));
        }

        frame.extend_from_slice(&available[..take]);
        reader.consume(take);

        if newline.is_some() {
            return Ok(Some(frame));
        }
    }
}

fn trim_newline(frame: &[u8]) -> &[u8] {
    let mut end = frame.len();
    if end > 0 && frame[end - 1] == b'\n' {
        end -= 1;
    }
    if end > 0 && frame[end - 1] == b'\r' {
        end -= 1;
    }
    &frame[..end]
}

fn parse_args() -> Result<Config, String> {
    let args: Vec<String> = env::args().skip(1).collect();
    let separator = args
        .iter()
        .position(|value| value == "--")
        .ok_or_else(|| "missing -- before MCP server command".to_string())?;

    let options = &args[..separator];
    let command_parts = &args[separator + 1..];
    let command = command_parts
        .first()
        .cloned()
        .ok_or_else(|| "missing MCP server command".to_string())?;
    let command_args = command_parts[1..].to_vec();

    let mut server_id = None;
    let mut device_id = None;
    let mut token_file = None;
    let mut target = None;
    let mut unavailable_mode = UnavailableMode::Deny;

    let mut index = 0usize;
    while index < options.len() {
        match options[index].as_str() {
            "--server-id" => {
                index += 1;
                server_id = options.get(index).cloned();
            }
            "--device-id" => {
                index += 1;
                device_id = options.get(index).cloned();
            }
            "--token-file" => {
                index += 1;
                token_file = options.get(index).map(PathBuf::from);
            }
            "--tcp" => {
                index += 1;
                let port = options
                    .get(index)
                    .and_then(|value| value.parse::<u16>().ok())
                    .filter(|port| *port >= 1024)
                    .ok_or_else(|| "invalid --tcp port".to_string())?;
                set_target(&mut target, LocalAuthorizationTarget::Tcp(port))?;
            }
            #[cfg(unix)]
            "--unix" => {
                index += 1;
                let path = options
                    .get(index)
                    .map(PathBuf::from)
                    .ok_or_else(|| "missing --unix path".to_string())?;
                set_target(&mut target, LocalAuthorizationTarget::Unix(path))?;
            }
            #[cfg(windows)]
            "--pipe" => {
                index += 1;
                let name = options
                    .get(index)
                    .cloned()
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| "missing --pipe name".to_string())?;
                set_target(
                    &mut target,
                    LocalAuthorizationTarget::WindowsPipe(name),
                )?;
            }
            "--on-unavailable" => {
                index += 1;
                unavailable_mode = match options.get(index).map(String::as_str) {
                    Some("deny") => UnavailableMode::Deny,
                    Some("allow") => UnavailableMode::Allow,
                    _ => {
                        return Err(
                            "--on-unavailable must be deny or allow".to_string()
                        )
                    }
                };
            }
            other => return Err(format!("unknown option: {other}")),
        }
        index += 1;
    }

    let server_id = server_id
        .filter(|value| !value.is_empty() && value.len() <= 256)
        .ok_or_else(|| "missing/invalid --server-id".to_string())?;
    let device_id = device_id
        .filter(|value| !value.is_empty() && value.len() <= 256)
        .ok_or_else(|| "missing/invalid --device-id".to_string())?;
    let token_file =
        token_file.ok_or_else(|| "missing --token-file".to_string())?;
    let target = target.ok_or_else(|| "missing local Nexus transport".to_string())?;

    Ok(Config {
        server_id,
        device_id,
        token_file,
        target,
        unavailable_mode,
        command,
        command_args,
    })
}

fn set_target(
    slot: &mut Option<LocalAuthorizationTarget>,
    value: LocalAuthorizationTarget,
) -> Result<(), String> {
    if slot.is_some() {
        return Err("select exactly one local Nexus transport".to_string());
    }
    *slot = Some(value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_agent_core::AgentActionKind;

    #[test]
    fn tool_call_normalizes_without_arguments() {
        let config = Config {
            server_id: "filesystem".into(),
            device_id: "device-1".into(),
            token_file: "token".into(),
            target: LocalAuthorizationTarget::Tcp(8765),
            unavailable_mode: UnavailableMode::Deny,
            command: "server".into(),
            command_args: vec![],
        };
        let message = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "write_file",
                "arguments": {
                    "path": "/secret",
                    "content": "must-not-leak"
                }
            }
        });

        let event = normalize_mcp_action(
            &config.server_id,
            &config.device_id,
            &message,
            "test",
        )
        .unwrap();
        assert_eq!(event.tool_name.as_deref(), Some("write_file"));
        assert_eq!(event.operation, "call");
        assert!(event.resource.is_none());

        let serialized = serde_json::to_string(&event).unwrap();
        assert!(!serialized.contains("must-not-leak"));
        assert!(!serialized.contains("/secret"));
    }

    #[test]
    fn resource_read_preserves_only_uri() {
        let config = Config {
            server_id: "docs".into(),
            device_id: "device-1".into(),
            token_file: "token".into(),
            target: LocalAuthorizationTarget::Tcp(8765),
            unavailable_mode: UnavailableMode::Deny,
            command: "server".into(),
            command_args: vec![],
        };
        let message = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "r1",
            "method": "resources/read",
            "params": {"uri": "file:///docs/manual.pdf"}
        });

        let event = normalize_mcp_action(
            &config.server_id,
            &config.device_id,
            &message,
            "test",
        )
        .unwrap();
        assert_eq!(event.kind, AgentActionKind::McpResourceRead);
        assert_eq!(
            event.resource.as_deref(),
            Some("file:///docs/manual.pdf")
        );
    }

    #[test]
    fn bounded_frame_reader_rejects_oversized_line() {
        let data = vec![b'x'; MAX_MCP_FRAME_BYTES + 1];
        let mut reader = BufReader::new(data.as_slice());
        assert!(read_frame(&mut reader).is_err());
    }
}
