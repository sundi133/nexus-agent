use nexus_agent_core::{
    AgentActionKind, AgentActionRule, DecisionAction, EnforcementMode, PolicyBundle,
};
use nexus_agent_runtime::{spawn_local_ingest, LocalIngestAuth};
use std::{
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
        Arc, RwLock,
    },
    thread,
    time::{Duration, Instant},
};
use tempfile::tempdir;

fn free_port() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    listener.local_addr().unwrap().port()
}

fn write_secret(path: &std::path::Path, value: &str) {
    fs::write(path, value).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn spawn_fake_upstream() -> (
    SocketAddr,
    Arc<AtomicUsize>,
    Arc<AtomicBool>,
    thread::JoinHandle<()>,
) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let hits_thread = hits.clone();
    let stop_thread = stop.clone();

    let handle = thread::spawn(move || {
        while !stop_thread.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    hits_thread.fetch_add(1, Ordering::Relaxed);
                    stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();

                    let mut request = Vec::new();
                    let mut buffer = [0u8; 4096];
                    let mut expected_total = None;

                    loop {
                        match stream.read(&mut buffer) {
                            Ok(0) => break,
                            Ok(read) => {
                                request.extend_from_slice(&buffer[..read]);
                                if expected_total.is_none() {
                                    if let Some(header_end) = request
                                        .windows(4)
                                        .position(|window| window == b"\r\n\r\n")
                                        .map(|offset| offset + 4)
                                    {
                                        let header =
                                            String::from_utf8_lossy(&request[..header_end]);
                                        let content_length = header
                                            .lines()
                                            .find_map(|line| {
                                                let (name, value) = line.split_once(':')?;
                                                name.eq_ignore_ascii_case("content-length")
                                                    .then(|| value.trim().parse::<usize>().ok())
                                                    .flatten()
                                            })
                                            .unwrap_or(0);
                                        expected_total = Some(header_end + content_length);
                                    }
                                }

                                if expected_total.is_some_and(|total| request.len() >= total) {
                                    break;
                                }
                            }
                            Err(error)
                                if matches!(
                                    error.kind(),
                                    std::io::ErrorKind::WouldBlock
                                        | std::io::ErrorKind::TimedOut
                                ) =>
                            {
                                break;
                            }
                            Err(_) => break,
                        }
                    }

                    let body =
                        br#"{"jsonrpc":"2.0","id":1,"result":{"upstream":true}}"#;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes());
                    let _ = stream.write_all(body);
                    let _ = stream.flush();
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });

    (address, hits, stop, handle)
}

fn wait_for_listener(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        if Instant::now() >= deadline {
            panic!("proxy did not start");
        }
        thread::sleep(Duration::from_millis(25));
    }
}

#[test]
fn streamable_http_proxy_forwards_allowed_and_blocks_denied_tool_call() {
    let token = "z".repeat(32);
    let auth_port = free_port();
    let proxy_port = free_port();

    let policy = PolicyBundle {
        version: 300,
        mode: EnforcementMode::Enforce,
        rules: vec![],
        agent_action_rules: vec![AgentActionRule {
            id: "deny-delete".into(),
            action: DecisionAction::Deny,
            kinds: vec![AgentActionKind::McpToolCall],
            agent_ids: vec![],
            mcp_servers: vec!["integration-http".into()],
            tool_names: vec!["delete_file".into()],
            operations: vec!["call".into()],
            resource_prefixes: vec![],
            risk_tags: vec![],
        }],
        ransomware_response: None,
    };

    let (audit_tx, _audit_rx) = mpsc::channel();
    let _auth_server = spawn_local_ingest(
        auth_port,
        LocalIngestAuth::LegacyToken(token.clone()),
        Arc::new(RwLock::new(Some(policy))),
        audit_tx,
    )
    .unwrap();

    let (upstream_address, upstream_hits, stop_upstream, upstream_thread) =
        spawn_fake_upstream();

    let dir = tempdir().unwrap();
    let token_path = dir.path().join("proxy.token");
    write_secret(&token_path, &token);

    let binary = env!("CARGO_BIN_EXE_nexus-mcp-http-proxy");
    let mut proxy = Command::new(binary)
        .args([
            "--listen",
            &format!("127.0.0.1:{proxy_port}"),
            "--upstream",
            &format!("http://{upstream_address}/mcp"),
            "--server-id",
            "integration-http",
            "--device-id",
            "integration-device",
            "--token-file",
            token_path.to_str().unwrap(),
            "--tcp",
            &auth_port.to_string(),
            "--on-unavailable",
            "deny",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    wait_for_listener(proxy_port);

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let url = format!("http://127.0.0.1:{proxy_port}/mcp");

    let allowed = client
        .post(&url)
        .header("Content-Type", "application/json")
        .body(
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {}
            })
            .to_string(),
        )
        .send()
        .unwrap();

    assert_eq!(allowed.status().as_u16(), 200);
    let allowed_body: serde_json::Value = allowed.json().unwrap();
    assert_eq!(allowed_body["result"]["upstream"], true);
    assert_eq!(upstream_hits.load(Ordering::Relaxed), 1);

    let denied = client
        .post(&url)
        .header("Content-Type", "application/json")
        .body(
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "delete_file",
                    "arguments": {"path": "/tmp/demo"}
                }
            })
            .to_string(),
        )
        .send()
        .unwrap();

    assert_eq!(denied.status().as_u16(), 200);
    let denied_body: serde_json::Value = denied.json().unwrap();
    assert_eq!(denied_body["error"]["code"], -32003);

    thread::sleep(Duration::from_millis(100));
    assert_eq!(
        upstream_hits.load(Ordering::Relaxed),
        1,
        "denied tool call must not reach upstream"
    );

    let _ = proxy.kill();
    let _ = proxy.wait();

    stop_upstream.store(true, Ordering::Relaxed);
    upstream_thread.join().unwrap();
}
