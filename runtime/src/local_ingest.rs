use nexus_agent_core::{
    AgentActionDecision, AgentActionEvent, DecisionAction, PolicyBundle,
};
use serde::Serialize;
use std::{
    io::{self, BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    sync::{
        mpsc::Sender,
        Arc, RwLock,
    },
    thread,
    time::Duration,
};

#[cfg(windows)]
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, DuplicateHandle, GetLastError, HANDLE, DUPLICATE_SAME_ACCESS,
        ERROR_PIPE_CONNECTED, INVALID_HANDLE_VALUE,
    },
    Storage::FileSystem::{ReadFile, WriteFile, PIPE_ACCESS_DUPLEX},
    System::{
        Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe,
            GetNamedPipeClientProcessId, PIPE_READMODE_BYTE,
            PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
        },
        Threading::{
            GetCurrentProcess, OpenProcess, QueryFullProcessImageNameW,
            PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
        },
    },
};

#[cfg(unix)]
use std::{
    fs,
    os::{
        fd::AsRawFd,
        unix::{
            fs::PermissionsExt,
            net::{UnixListener, UnixStream},
        },
    },
    path::Path,
};

const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_BODY_BYTES: usize = 64 * 1024;
#[cfg(windows)]
const PIPE_REJECT_REMOTE_CLIENTS_FLAG: u32 = 0x0000_0008;

#[derive(Debug, Clone)]
pub struct ProducerCredential {
    pub agent_id: String,
    pub token: String,
    pub expected_uid: Option<u32>,
    pub executable_paths: Vec<PathBuf>,
}

#[derive(Debug, Clone)]
pub enum LocalIngestAuth {
    LegacyToken(String),
    BoundProducers(Vec<ProducerCredential>),
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ProducerAttestation {
    pub transport: String,
    pub credential_bound: bool,
    pub kernel_peer: bool,
    pub pid: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub executable_path: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentActionAuditRecord {
    pub event: AgentActionEvent,
    pub decision: AgentActionDecision,
    pub producer_attestation: ProducerAttestation,
}

#[derive(Debug, Clone, Default)]
struct PeerIdentity {
    pid: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
    executable_path: Option<String>,
    transport: &'static str,
}

struct AuthenticatedProducer {
    agent_id: Option<String>,
    attestation: ProducerAttestation,
}

trait LocalStream: Read + Write + Sized {
    fn try_clone_stream(&self) -> io::Result<Self>;
    fn configure_timeouts(&self) -> io::Result<()>;
}

impl LocalStream for TcpStream {
    fn try_clone_stream(&self) -> io::Result<Self> {
        self.try_clone()
    }

    fn configure_timeouts(&self) -> io::Result<()> {
        self.set_read_timeout(Some(Duration::from_secs(2)))?;
        self.set_write_timeout(Some(Duration::from_secs(2)))
    }
}

#[cfg(windows)]
struct WindowsPipeStream {
    handle: HANDLE,
}

#[cfg(windows)]
impl WindowsPipeStream {
    fn new(handle: HANDLE) -> Self {
        Self { handle }
    }
}

#[cfg(windows)]
impl Read for WindowsPipeStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let mut read = 0u32;
        let length = buffer.len().min(u32::MAX as usize) as u32;
        let ok = unsafe {
            ReadFile(
                self.handle,
                buffer.as_mut_ptr(),
                length,
                &mut read,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(read as usize)
    }
}

#[cfg(windows)]
impl Write for WindowsPipeStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let mut written = 0u32;
        let length = buffer.len().min(u32::MAX as usize) as u32;
        let ok = unsafe {
            WriteFile(
                self.handle,
                buffer.as_ptr(),
                length,
                &mut written,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(written as usize)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(windows)]
impl LocalStream for WindowsPipeStream {
    fn try_clone_stream(&self) -> io::Result<Self> {
        let current_process = unsafe { GetCurrentProcess() };
        let mut duplicate: HANDLE = std::ptr::null_mut();
        let ok = unsafe {
            DuplicateHandle(
                current_process,
                self.handle,
                current_process,
                &mut duplicate,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self::new(duplicate))
    }

    fn configure_timeouts(&self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(windows)]
impl Drop for WindowsPipeStream {
    fn drop(&mut self) {
        unsafe {
            let _ = DisconnectNamedPipe(self.handle);
            let _ = CloseHandle(self.handle);
        }
    }
}

#[cfg(unix)]
impl LocalStream for UnixStream {
    fn try_clone_stream(&self) -> io::Result<Self> {
        self.try_clone()
    }

    fn configure_timeouts(&self) -> io::Result<()> {
        self.set_read_timeout(Some(Duration::from_secs(2)))?;
        self.set_write_timeout(Some(Duration::from_secs(2)))
    }
}

pub fn spawn_local_ingest(
    port: u16,
    auth: LocalIngestAuth,
    policy: Arc<RwLock<Option<PolicyBundle>>>,
    sender: Sender<AgentActionAuditRecord>,
) -> io::Result<thread::JoinHandle<()>> {
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    listener.set_nonblocking(true)?;

    Ok(thread::spawn(move || loop {
        match listener.accept() {
            Ok((stream, _)) => {
                let peer = PeerIdentity {
                    transport: "tcp_loopback",
                    ..PeerIdentity::default()
                };
                let _ = handle_connection(stream, &auth, &policy, &sender, peer);
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

#[cfg(unix)]
pub fn spawn_local_ingest_unix(
    socket_path: PathBuf,
    auth: LocalIngestAuth,
    policy: Arc<RwLock<Option<PolicyBundle>>>,
    sender: Sender<AgentActionAuditRecord>,
) -> io::Result<thread::JoinHandle<()>> {
    if let Some(parent) = socket_path.parent() {
        fs::create_dir_all(parent)?;
    }
    match fs::remove_file(&socket_path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    let listener = UnixListener::bind(&socket_path)?;
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o660))?;
    listener.set_nonblocking(true)?;

    Ok(thread::spawn(move || loop {
        match listener.accept() {
            Ok((stream, _)) => {
                let peer = unix_peer_identity(&stream).unwrap_or_else(|_| PeerIdentity {
                    transport: "unix_socket_unattested",
                    ..PeerIdentity::default()
                });
                let _ = handle_connection(stream, &auth, &policy, &sender, peer);
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

#[cfg(windows)]
pub fn spawn_local_ingest_windows_pipe(
    pipe_name: String,
    auth: LocalIngestAuth,
    policy: Arc<RwLock<Option<PolicyBundle>>>,
    sender: Sender<AgentActionAuditRecord>,
) -> io::Result<thread::JoinHandle<()>> {
    let full_name = if pipe_name.starts_with(r"\\.\pipe\") {
        pipe_name
    } else {
        format!(r"\\.\pipe\{pipe_name}")
    };
    let mut wide_name: Vec<u16> = full_name.encode_utf16().collect();
    wide_name.push(0);

    Ok(thread::spawn(move || loop {
        let handle = unsafe {
            CreateNamedPipeW(
                wide_name.as_ptr(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS_FLAG,
                PIPE_UNLIMITED_INSTANCES,
                64 * 1024,
                64 * 1024,
                0,
                std::ptr::null(),
            )
        };

        if handle == INVALID_HANDLE_VALUE {
            thread::sleep(Duration::from_millis(250));
            continue;
        }

        let connected = unsafe { ConnectNamedPipe(handle, std::ptr::null_mut()) };
        if connected == 0 {
            let error = unsafe { GetLastError() };
            if error != ERROR_PIPE_CONNECTED {
                unsafe {
                    let _ = CloseHandle(handle);
                }
                thread::sleep(Duration::from_millis(50));
                continue;
            }
        }

        let mut client_pid = 0u32;
        let pid_ok = unsafe { GetNamedPipeClientProcessId(handle, &mut client_pid) };
        let executable_path = if pid_ok != 0 && client_pid != 0 {
            windows_process_path(client_pid)
        } else {
            None
        };

        let peer = PeerIdentity {
            pid: (pid_ok != 0 && client_pid != 0).then_some(client_pid),
            uid: None,
            gid: None,
            executable_path,
            transport: "windows_named_pipe_client_pid",
        };

        let stream = WindowsPipeStream::new(handle);
        let _ = handle_connection(stream, &auth, &policy, &sender, peer);
    }))
}

#[cfg(windows)]
fn windows_process_path(pid: u32) -> Option<String> {
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return None;
    }

    let mut buffer = vec![0u16; 32768];
    let mut size = buffer.len() as u32;
    let ok = unsafe {
        QueryFullProcessImageNameW(
            process,
            PROCESS_NAME_WIN32,
            buffer.as_mut_ptr(),
            &mut size,
        )
    };
    unsafe {
        let _ = CloseHandle(process);
    }
    if ok == 0 || size == 0 {
        return None;
    }

    Some(String::from_utf16_lossy(&buffer[..size as usize]))
}

fn handle_connection<S: LocalStream>(
    mut stream: S,
    auth: &LocalIngestAuth,
    policy: &Arc<RwLock<Option<PolicyBundle>>>,
    sender: &Sender<AgentActionAuditRecord>,
    peer: PeerIdentity,
) -> io::Result<()> {
    stream.configure_timeouts()?;

    let cloned = stream.try_clone_stream()?;
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
        return write_error_response(&mut stream, 404, "not found");
    }

    let supplied_token = authorization
        .as_deref()
        .and_then(|value| value.strip_prefix("Bearer "));
    let Some(supplied_token) = supplied_token else {
        return write_error_response(&mut stream, 401, "unauthorized");
    };
    let Some(authenticated) = authenticate_producer(auth, supplied_token, &peer) else {
        return write_error_response(&mut stream, 401, "unauthorized or producer attestation failed");
    };

    let Some(body_len) = content_length else {
        return write_error_response(&mut stream, 411, "content-length required");
    };
    if body_len == 0 || body_len > MAX_BODY_BYTES {
        return write_error_response(&mut stream, 413, "invalid body size");
    }

    let mut body = vec![0u8; body_len];
    reader.read_exact(&mut body)?;

    let mut event: AgentActionEvent = match serde_json::from_slice(&body) {
        Ok(event) => event,
        Err(_) => return write_error_response(&mut stream, 400, "invalid JSON"),
    };
    if event.validate().is_err() {
        return write_error_response(&mut stream, 422, "invalid agent action");
    }

    if let Some(bound_agent_id) = authenticated.agent_id.as_deref() {
        if event
            .agent_id
            .as_deref()
            .is_some_and(|claimed| claimed != bound_agent_id)
        {
            return write_error_response(
                &mut stream,
                403,
                "agent identity does not match producer credential",
            );
        }
        event.agent_id = Some(bound_agent_id.to_string());
    } else {
        event.agent_id = None;
    }

    if let Some(peer_pid) = authenticated.attestation.pid {
        if event.pid.is_some_and(|claimed| claimed != peer_pid) {
            return write_error_response(
                &mut stream,
                403,
                "process identity does not match kernel peer credentials",
            );
        }
        event.pid = Some(peer_pid);
    }

    let decision = decide_agent_action(policy, &event);
    let audit = AgentActionAuditRecord {
        event,
        decision: decision.clone(),
        producer_attestation: authenticated.attestation,
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

fn authenticate_producer(
    auth: &LocalIngestAuth,
    supplied_token: &str,
    peer: &PeerIdentity,
) -> Option<AuthenticatedProducer> {
    match auth {
        LocalIngestAuth::LegacyToken(token) => constant_time_eq(
            supplied_token.as_bytes(),
            token.as_bytes(),
        )
        .then(|| AuthenticatedProducer {
            agent_id: None,
            attestation: attestation_from_peer(peer, false),
        }),
        LocalIngestAuth::BoundProducers(producers) => {
            let mut matched: Option<&ProducerCredential> = None;
            for producer in producers {
                if constant_time_eq(
                    supplied_token.as_bytes(),
                    producer.token.as_bytes(),
                ) {
                    matched = Some(producer);
                }
            }

            let producer = matched?;
            if producer
                .expected_uid
                .is_some_and(|expected| peer.uid != Some(expected))
            {
                return None;
            }

            if !producer.executable_paths.is_empty() {
                let peer_path = peer.executable_path.as_deref()?;
                if !producer
                    .executable_paths
                    .iter()
                    .any(|candidate| candidate.to_string_lossy() == peer_path)
                {
                    return None;
                }
            }

            Some(AuthenticatedProducer {
                agent_id: Some(producer.agent_id.clone()),
                attestation: attestation_from_peer(peer, true),
            })
        }
    }
}

fn attestation_from_peer(peer: &PeerIdentity, credential_bound: bool) -> ProducerAttestation {
    ProducerAttestation {
        transport: peer.transport.to_string(),
        credential_bound,
        kernel_peer: peer.uid.is_some() || peer.pid.is_some(),
        pid: peer.pid,
        uid: peer.uid,
        gid: peer.gid,
        executable_path: peer.executable_path.clone(),
    }
}

#[cfg(target_os = "linux")]
fn unix_peer_identity(stream: &UnixStream) -> io::Result<PeerIdentity> {
    let fd = stream.as_raw_fd();
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;

    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }

    let pid = u32::try_from(credentials.pid).ok();
    let executable_path = pid.and_then(|pid| {
        fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .map(|path| path.to_string_lossy().into_owned())
    });

    Ok(PeerIdentity {
        pid,
        uid: Some(credentials.uid),
        gid: Some(credentials.gid),
        executable_path,
        transport: "unix_socket_linux_peercred",
    })
}

#[cfg(all(unix, not(target_os = "linux")))]
fn unix_peer_identity(stream: &UnixStream) -> io::Result<PeerIdentity> {
    let fd = stream.as_raw_fd();
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    let result = unsafe { libc::getpeereid(fd, &mut uid, &mut gid) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(PeerIdentity {
        pid: None,
        uid: Some(uid),
        gid: Some(gid),
        executable_path: None,
        transport: "unix_socket_peer_eid",
    })
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

fn write_decision_response<W: Write>(
    stream: &mut W,
    status: u16,
    decision: &AgentActionDecision,
) -> io::Result<()> {
    let reason = if status == 403 { "Forbidden" } else { "OK" };
    let body = serde_json::to_string(decision)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )?;
    stream.flush()
}

fn write_error_response<W: Write>(
    stream: &mut W,
    status: u16,
    message: &str,
) -> io::Result<()> {
    let reason = match status {
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
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
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
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
                agent_ids: vec!["agent-1".into()],
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
    fn legacy_token_authenticates_without_agent_identity() {
        let auth = LocalIngestAuth::LegacyToken("a".repeat(32));
        let peer = PeerIdentity {
            transport: "tcp_loopback",
            ..PeerIdentity::default()
        };
        let authenticated =
            authenticate_producer(&auth, &"a".repeat(32), &peer).unwrap();
        assert!(authenticated.agent_id.is_none());
        assert!(!authenticated.attestation.kernel_peer);
        assert!(authenticate_producer(&auth, &"b".repeat(32), &peer).is_none());
    }

    #[test]
    fn bound_producer_enforces_peer_uid_and_executable() {
        let auth = LocalIngestAuth::BoundProducers(vec![ProducerCredential {
            agent_id: "agent-b".into(),
            token: "b".repeat(32),
            expected_uid: Some(1000),
            executable_paths: vec!["/usr/local/bin/agent-b".into()],
        }]);
        let peer = PeerIdentity {
            pid: Some(44),
            uid: Some(1000),
            gid: Some(1000),
            executable_path: Some("/usr/local/bin/agent-b".into()),
            transport: "unix_socket_linux_peercred",
        };
        let authenticated =
            authenticate_producer(&auth, &"b".repeat(32), &peer).unwrap();
        assert_eq!(authenticated.agent_id.as_deref(), Some("agent-b"));
        assert!(authenticated.attestation.kernel_peer);

        let wrong_uid = PeerIdentity {
            uid: Some(1001),
            ..peer.clone()
        };
        assert!(authenticate_producer(&auth, &"b".repeat(32), &wrong_uid).is_none());

        let wrong_exe = PeerIdentity {
            executable_path: Some("/tmp/other".into()),
            ..peer
        };
        assert!(authenticate_producer(&auth, &"b".repeat(32), &wrong_exe).is_none());
    }

    #[cfg(windows)]
    #[test]
    fn windows_pipe_name_prefix_is_documented_by_runtime() {
        let configured = "VotalNexusAgentActions";
        let full = format!(r"\\.\pipe\{configured}");
        assert_eq!(full, r"\\.\pipe\VotalNexusAgentActions");
    }

    #[cfg(unix)]
    #[test]
    fn unix_peer_identity_is_kernel_derived() {
        let (left, _right) = UnixStream::pair().unwrap();
        let peer = unix_peer_identity(&left).unwrap();
        assert!(peer.uid.is_some());
        assert!(peer.gid.is_some());
        assert!(peer.transport.starts_with("unix_socket_"));
        #[cfg(target_os = "linux")]
        {
            assert_eq!(peer.pid, Some(std::process::id()));
            assert!(peer.executable_path.is_some());
        }
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
            producer_attestation: ProducerAttestation {
                transport: "test".into(),
                credential_bound: true,
                kernel_peer: true,
                pid: Some(42),
                uid: Some(1000),
                gid: Some(1000),
                executable_path: Some("/usr/bin/test".into()),
            },
        })
        .unwrap();
        let record = rx.recv().unwrap();
        assert_eq!(record.decision.action, DecisionAction::Alert);
        assert!(record.decision.would_deny);
        assert!(record.producer_attestation.kernel_peer);
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
