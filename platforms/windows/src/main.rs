#[cfg(windows)]
mod etw;

#[cfg(not(windows))]
fn main() {
    eprintln!("nexus-agent-windows is only supported on Windows");
}

#[cfg(windows)]
mod service {
    use crate::etw::{EtwProcessStart, ProcessTrace};
    use nexus_agent_core::{verify_signed_policy, AgentHealth, CapabilityState, EventKind, PolicyBundle, SecurityEvent, SignedPolicyEnvelope};
    use std::{
        collections::HashMap,
        ffi::OsString,
        fs::{create_dir_all, OpenOptions},
        io::{self, Write},
        mem::{size_of, zeroed},
        path::Path,
        sync::mpsc,
        time::Duration,
    };
    use time::{format_description::well_known::Rfc3339, OffsetDateTime};
    use windows_service::{
        define_windows_service,
        service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher, Result,
    };
    use windows_sys::Win32::{
        Foundation::{CloseHandle, INVALID_HANDLE_VALUE},
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
                TH32CS_SNAPPROCESS,
            },
            Threading::{
                OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
                PROCESS_QUERY_LIMITED_INFORMATION,
            },
        },
    };

    const SERVICE_NAME: &str = "VotalNexusAgent";
    const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;
    const EVENT_LOG_PATH: &str = r"C:\ProgramData\Votal\Nexus\events.jsonl";
    const POLICY_PATH: &str = r"C:\ProgramData\Votal\Nexus\policy.signed.json";
    // Development placeholder. Replace with Votal's pinned 32-byte Ed25519 public key.
    const POLICY_PUBLIC_KEY: [u8; 32] = [0; 32];

    #[derive(Debug, Clone)]
    struct ProcessInfo {
        pid: u32,
        parent_pid: u32,
        image_name: String,
    }

    pub fn run() -> Result<()> {
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)
    }

    define_windows_service!(ffi_service_main, service_main);

    pub fn service_main(_arguments: Vec<OsString>) {
        if let Err(error) = run_service() {
            let _ = write_diagnostic(&format!("service error: {error}"));
        }
    }

    fn run_service() -> Result<()> {
        let (shutdown_tx, shutdown_rx) = mpsc::channel();

        let event_handler = move |control_event| -> ServiceControlHandlerResult {
            match control_event {
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                ServiceControl::Stop => {
                    let _ = shutdown_tx.send(());
                    ServiceControlHandlerResult::NoError
                }
                _ => ServiceControlHandlerResult::NotImplemented,
            }
        };

        let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

        status_handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })?;

        let policy = load_verified_policy();
        let _ = write_diagnostic(if policy.is_some() {
            "signed policy verified; Windows service remains shadow-only"
        } else {
            "no verified policy loaded; telemetry-only"
        });

        let (etw_tx, etw_rx) = mpsc::channel();

        match ProcessTrace::start(etw_tx) {
            Ok(_trace) => {
                let _ = write_diagnostic("ETW process-start telemetry active");
                let health = build_health(
                    policy.as_ref(),
                    CapabilityState::Active,
                    "ETW Microsoft-Windows-Kernel-Process",
                );
                let _ = write_health(&health);
                run_etw_loop(&shutdown_rx, &etw_rx, policy.as_ref());
            }
            Err(error) => {
                let detail = format!("ETW unavailable; Tool Help polling fallback: {error}");
                let _ = write_diagnostic(&detail);
                let health = build_health(
                    policy.as_ref(),
                    CapabilityState::Fallback,
                    &detail,
                );
                let _ = write_health(&health);
                run_snapshot_loop(&shutdown_rx, policy.as_ref());
            }
        }

        status_handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })?;

        Ok(())
    }

    fn run_etw_loop(
        shutdown_rx: &mpsc::Receiver<()>,
        etw_rx: &mpsc::Receiver<EtwProcessStart>,
        policy: Option<&PolicyBundle>,
    ) {
        loop {
            if shutdown_rx.try_recv().is_ok() {
                break;
            }

            match etw_rx.recv_timeout(Duration::from_millis(250)) {
                Ok(start) => {
                    let process = ProcessInfo {
                        pid: start.pid,
                        parent_pid: start.parent_pid,
                        image_name: start.image_name,
                    };
                    let full_path = query_process_path(process.pid)
                        .unwrap_or_else(|| process.image_name.clone());
                    let _ = emit_process_start(&process, full_path, policy);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    let _ = write_diagnostic("ETW event channel disconnected");
                    break;
                }
            }
        }
    }

    fn run_snapshot_loop(
        shutdown_rx: &mpsc::Receiver<()>,
        policy: Option<&PolicyBundle>,
    ) {
        let mut known = snapshot_processes().unwrap_or_default();

        loop {
            match shutdown_rx.recv_timeout(Duration::from_secs(1)) {
                Ok(_) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }

            match snapshot_processes() {
                Ok(current) => {
                    for (pid, process) in &current {
                        if !known.contains_key(pid) {
                            let full_path = query_process_path(*pid)
                                .unwrap_or_else(|| process.image_name.clone());
                            let _ = emit_process_start(process, full_path, policy);
                        }
                    }
                    known = current;
                }
                Err(error) => {
                    let _ = write_diagnostic(&format!("process snapshot failed: {error}"));
                }
            }
        }
    }

    fn emit_process_start(process: &ProcessInfo, executable_path: String, policy: Option<&PolicyBundle>) -> io::Result<()> {
        let now = OffsetDateTime::now_utc();
        let timestamp = now
            .format(&Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string());
        let device_id =
            std::env::var("COMPUTERNAME").unwrap_or_else(|_| "windows-device".to_string());

        let event = SecurityEvent {
            event_id: format!("windows-process-{}-{}", process.pid, now.unix_timestamp_nanos()),
            timestamp,
            device_id,
            kind: EventKind::ProcessExec,
            pid: Some(process.pid),
            parent_pid: Some(process.parent_pid),
            executable_path: Some(executable_path),
            target_path: None,
            destination_host: None,
        };

        append_json_line(&event, policy)
    }

    fn append_json_line(event: &SecurityEvent, policy: Option<&PolicyBundle>) -> io::Result<()> {
        let path = Path::new(EVENT_LOG_PATH);
        if let Some(parent) = path.parent() {
            create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new().create(true).append(true).open(path)?;
        let record = if let Some(policy) = policy {
            let decision = policy.evaluate(event);
            serde_json::json!({
                "event": event,
                "policy_version": decision.policy_version,
                "decision": format!("{:?}", decision.action).to_lowercase(),
                "would_deny": decision.would_deny,
                "enforcement": "shadow"
            })
        } else {
            serde_json::json!({
                "event": event,
                "policy_version": null,
                "decision": "allow",
                "would_deny": false,
                "enforcement": "telemetry_only"
            })
        };
        serde_json::to_writer(&mut file, &record)?;
        file.write_all(b"\n")?;
        Ok(())
    }


    fn build_health(
        policy: Option<&PolicyBundle>,
        telemetry_state: CapabilityState,
        telemetry_detail: &str,
    ) -> AgentHealth {
        let policy_version = policy.map(|policy| policy.version);
        let policy_state = if policy.is_some() {
            CapabilityState::Active
        } else {
            CapabilityState::Unavailable
        };
        let enforcement_state = if policy.is_some() {
            CapabilityState::Shadow
        } else {
            CapabilityState::Unavailable
        };

        AgentHealth::new("windows", policy_version)
            .with_capability(
                "policy_verification",
                policy_state,
                if policy.is_some() {
                    "Ed25519 signed policy verified"
                } else {
                    "no verified policy loaded"
                },
            )
            .with_capability("process_telemetry", telemetry_state, telemetry_detail)
            .with_capability(
                "process_enforcement",
                enforcement_state,
                if policy.is_some() {
                    "policy decisions are shadow-only; no process blocking"
                } else {
                    "no verified policy; process blocking unavailable"
                },
            )
    }

    fn write_health(health: &AgentHealth) -> io::Result<()> {
        let path = Path::new(HEALTH_PATH);
        if let Some(parent) = path.parent() {
            create_dir_all(parent)?;
        }
        let mut file = std::fs::File::create(path)?;
        serde_json::to_writer_pretty(&mut file, health)?;
        file.write_all(b"\n")?;
        Ok(())
    }

    fn load_verified_policy() -> Option<PolicyBundle> {
        if POLICY_PUBLIC_KEY.iter().all(|byte| *byte == 0) {
            return None;
        }

        let envelope_bytes = std::fs::read(POLICY_PATH).ok()?;
        let envelope: SignedPolicyEnvelope = serde_json::from_slice(&envelope_bytes).ok()?;
        verify_signed_policy(&envelope, &POLICY_PUBLIC_KEY).ok()
    }

    fn write_diagnostic(message: &str) -> io::Result<()> {
        let path = Path::new(EVENT_LOG_PATH);
        if let Some(parent) = path.parent() {
            create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new().create(true).append(true).open(path)?;
        writeln!(file, "{{\"diagnostic\":{}}}", serde_json::to_string(message)?)?;
        Ok(())
    }

    fn wide_string(buffer: &[u16]) -> String {
        let len = buffer.iter().position(|value| *value == 0).unwrap_or(buffer.len());
        String::from_utf16_lossy(&buffer[..len])
    }

    fn snapshot_processes() -> io::Result<HashMap<u32, ProcessInfo>> {
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snapshot == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error());
            }

            let mut entry: PROCESSENTRY32W = zeroed();
            entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
            let mut result = HashMap::new();

            if Process32FirstW(snapshot, &mut entry) != 0 {
                loop {
                    result.insert(
                        entry.th32ProcessID,
                        ProcessInfo {
                            pid: entry.th32ProcessID,
                            parent_pid: entry.th32ParentProcessID,
                            image_name: wide_string(&entry.szExeFile),
                        },
                    );

                    if Process32NextW(snapshot, &mut entry) == 0 {
                        break;
                    }
                }
            }

            let _ = CloseHandle(snapshot);
            Ok(result)
        }
    }

    fn query_process_path(pid: u32) -> Option<String> {
        unsafe {
            let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if process.is_null() {
                return None;
            }

            let mut buffer = [0u16; 32768];
            let mut size = buffer.len() as u32;
            let success = QueryFullProcessImageNameW(
                process,
                PROCESS_NAME_WIN32,
                buffer.as_mut_ptr(),
                &mut size,
            );
            let _ = CloseHandle(process);

            if success == 0 || size == 0 {
                return None;
            }

            Some(String::from_utf16_lossy(&buffer[..size as usize]))
        }
    }
}

#[cfg(windows)]
fn main() -> windows_service::Result<()> {
    service::run()
}
