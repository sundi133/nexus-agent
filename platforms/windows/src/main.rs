#[cfg(windows)]
mod etw;
#[cfg(windows)]
mod file_etw;
#[cfg(windows)]
mod wfp;

#[cfg(not(windows))]
fn main() {
    eprintln!("nexus-agent-windows is only supported on Windows");
}

#[cfg(windows)]
mod service {
    use crate::etw::{EtwProcessStart, ProcessTrace};
    use crate::file_etw::{EtwFileActivity, FileActivityKind, FileTrace};
    use crate::wfp::WfpSession;
    use nexus_agent_core::{
        plan_ransomware_response, verify_signed_policy, AgentHealth, CapabilityState,
        DecisionAction, DetectionConfig, EnforcementMode, EventKind, PolicyBundle,
        RansomwareAssessment, RansomwareResponseAction, RansomwareResponseDecision,
        RansomwareTracker, SecurityEvent, SignedPolicyEnvelope,
    };
    use std::{
        collections::{HashMap, HashSet},
        ffi::OsString,
        fs::{create_dir_all, OpenOptions},
        io::{self, Write},
        mem::{size_of, zeroed},
        net::Ipv4Addr,
        path::Path,
        sync::mpsc,
        time::{Duration, Instant},
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
                GetCurrentProcessId, OpenProcess, QueryFullProcessImageNameW, TerminateProcess,
                PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
            },
        },
    };

    const SERVICE_NAME: &str = "VotalNexusAgent";
    const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;
    const EVENT_LOG_PATH: &str = r"C:\ProgramData\Votal\Nexus\events.jsonl";
    const POLICY_PATH: &str = r"C:\ProgramData\Votal\Nexus\policy.signed.json";
    const POLICY_VERSION_PATH: &str = r"C:\ProgramData\Votal\Nexus\policy.version";
    const HEALTH_PATH: &str = r"C:\ProgramData\Votal\Nexus\health.json";
    const CONTAINMENT_DISABLE_PATH: &str =
        r"C:\ProgramData\Votal\Nexus\disable-containment";
    // Development placeholder. Replace with Votal's pinned 32-byte Ed25519 public key.
    const POLICY_PUBLIC_KEY: [u8; 32] = [0; 32];

    #[derive(Debug, Clone)]
    struct ProcessInfo {
        pid: u32,
        parent_pid: u32,
        image_name: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct NetworkEnforcementPlan {
        rule_id: String,
        remote_ipv4: String,
        application_path: Option<String>,
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
            "signed policy verified; process enforcement is shadow-only and supported network rules may be enforced dynamically"
        } else {
            "no verified policy loaded; telemetry-only"
        });

        let (network_session, network_state, network_detail) =
            configure_network_enforcement(policy.as_ref());

        let (file_tx, file_rx) = mpsc::channel();
        let (file_trace, file_state, file_detail) = match FileTrace::start(file_tx) {
            Ok(trace) => (
                Some(trace),
                CapabilityState::Active,
                "ETW Microsoft-Windows-Kernel-File with FileKey path correlation".to_string(),
            ),
            Err(error) => (
                None,
                CapabilityState::Unavailable,
                format!("Kernel-File ETW unavailable: {error}"),
            ),
        };

        let (etw_tx, etw_rx) = mpsc::channel();

        match ProcessTrace::start(etw_tx) {
            Ok(_trace) => {
                let _ = write_diagnostic("ETW process-start telemetry active");
                let health = build_health(
                    policy.as_ref(),
                    CapabilityState::Active,
                    "ETW Microsoft-Windows-Kernel-Process",
                    network_state,
                    &network_detail,
                    file_state,
                    &file_detail,
                );
                let _ = write_health(&health);
                run_etw_loop(&shutdown_rx, &etw_rx, &file_rx, policy.as_ref());
            }
            Err(error) => {
                let detail = format!("ETW unavailable; Tool Help polling fallback: {error}");
                let _ = write_diagnostic(&detail);
                let health = build_health(
                    policy.as_ref(),
                    CapabilityState::Fallback,
                    &detail,
                    network_state,
                    &network_detail,
                    file_state,
                    &file_detail,
                );
                let _ = write_health(&health);
                run_snapshot_loop(&shutdown_rx, &file_rx, policy.as_ref());
            }
        }

        drop(file_trace);
        drop(network_session);

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
        file_rx: &mpsc::Receiver<EtwFileActivity>,
        policy: Option<&PolicyBundle>,
    ) {
        let started = Instant::now();
        let mut ransomware_tracker = RansomwareTracker::new(DetectionConfig::default());
        let mut contained_pids = HashSet::new();

        loop {
            drain_file_activity(
                file_rx,
                policy,
                &mut ransomware_tracker,
                &mut contained_pids,
                started.elapsed().as_millis().min(u64::MAX as u128) as u64,
            );
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
                    mark_suspicious_if_policy_would_deny(
                        policy,
                        &mut ransomware_tracker,
                        process.pid,
                        Some(process.parent_pid),
                        &full_path,
                        started.elapsed().as_millis().min(u64::MAX as u128) as u64,
                    );
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
        file_rx: &mpsc::Receiver<EtwFileActivity>,
        policy: Option<&PolicyBundle>,
    ) {
        let mut known = snapshot_processes().unwrap_or_default();
        let started = Instant::now();
        let mut ransomware_tracker = RansomwareTracker::new(DetectionConfig::default());
        let mut contained_pids = HashSet::new();

        loop {
            drain_file_activity(
                file_rx,
                policy,
                &mut ransomware_tracker,
                &mut contained_pids,
                started.elapsed().as_millis().min(u64::MAX as u128) as u64,
            );
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
                            mark_suspicious_if_policy_would_deny(
                                policy,
                                &mut ransomware_tracker,
                                *pid,
                                Some(process.parent_pid),
                                &full_path,
                                started.elapsed().as_millis().min(u64::MAX as u128) as u64,
                            );
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

    fn drain_file_activity(
        file_rx: &mpsc::Receiver<EtwFileActivity>,
        policy: Option<&PolicyBundle>,
        ransomware_tracker: &mut RansomwareTracker,
        contained_pids: &mut HashSet<u32>,
        now_ms: u64,
    ) {
        while let Ok(activity) = file_rx.try_recv() {
            let _ = emit_file_activity(
                activity,
                policy,
                ransomware_tracker,
                contained_pids,
                now_ms,
            );
        }
    }

    fn mark_suspicious_if_policy_would_deny(
        policy: Option<&PolicyBundle>,
        tracker: &mut RansomwareTracker,
        pid: u32,
        parent_pid: Option<u32>,
        executable_path: &str,
        now_ms: u64,
    ) {
        let Some(policy) = policy else {
            return;
        };

        let event = SecurityEvent {
            event_id: "windows-exec-context".into(),
            timestamp: String::new(),
            device_id: String::new(),
            kind: EventKind::ProcessExec,
            pid: Some(pid),
            parent_pid,
            executable_path: Some(executable_path.to_string()),
            target_path: None,
            destination_host: None,
        };

        if policy.evaluate(&event).would_deny {
            tracker.mark_suspicious_process(pid, now_ms);
        }
    }

    fn execute_ransomware_response(
        response: Option<&RansomwareResponseDecision>,
        contained_pids: &mut HashSet<u32>,
    ) -> Option<String> {
        let response = response?;
        if !response.matched || !response.enforce {
            return None;
        }

        if response.action != RansomwareResponseAction::TerminateProcess {
            return Some(format!(
                "unsupported_enforcement_action:{:?}",
                response.action
            ));
        }

        if Path::new(CONTAINMENT_DISABLE_PATH).exists() {
            return Some("containment_disabled_by_local_switch".to_string());
        }

        let pid = response.pid;
        let self_pid = unsafe { GetCurrentProcessId() };
        if pid <= 4 || pid == self_pid {
            return Some(format!("refused_protected_pid:{pid}"));
        }

        if contained_pids.contains(&pid) {
            return Some(format!("already_contained:{pid}"));
        }

        unsafe {
            let process = OpenProcess(PROCESS_TERMINATE, 0, pid);
            if process.is_null() {
                return Some(format!(
                    "terminate_open_failed:{pid}:{}",
                    io::Error::last_os_error()
                ));
            }

            let result = TerminateProcess(process, 0x4E58);
            let error = if result == 0 {
                Some(io::Error::last_os_error())
            } else {
                None
            };
            let _ = CloseHandle(process);

            if let Some(error) = error {
                return Some(format!("terminate_failed:{pid}:{error}"));
            }
        }

        contained_pids.insert(pid);
        Some(format!("terminated_process:{pid}"))
    }

    fn emit_file_activity(
        activity: EtwFileActivity,
        policy: Option<&PolicyBundle>,
        ransomware_tracker: &mut RansomwareTracker,
        contained_pids: &mut HashSet<u32>,
        now_ms: u64,
    ) -> io::Result<()> {
        let renamed = activity.kind == FileActivityKind::Rename;
        let assessment = ransomware_tracker.observe_path(
            activity.pid,
            now_ms,
            &activity.path,
            renamed,
        );
        let ransomware_response = policy.and_then(|policy| {
            ransomware_tracker
                .features_for(activity.pid)
                .and_then(|features| {
                    plan_ransomware_response(policy, activity.pid, &features, &assessment)
                })
        });
        let containment =
            execute_ransomware_response(ransomware_response.as_ref(), contained_pids);

        let now = OffsetDateTime::now_utc();
        let timestamp = now
            .format(&Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string());
        let device_id =
            std::env::var("COMPUTERNAME").unwrap_or_else(|_| "windows-device".to_string());

        let kind = match activity.kind {
            FileActivityKind::Write => EventKind::FileWrite,
            FileActivityKind::Rename => EventKind::FileRename,
            FileActivityKind::Delete => EventKind::FileDelete,
            FileActivityKind::Create => EventKind::FileCreate,
        };

        let event = SecurityEvent {
            event_id: format!("windows-file-{}-{}", activity.pid, now.unix_timestamp_nanos()),
            timestamp,
            device_id,
            kind,
            pid: Some(activity.pid),
            parent_pid: None,
            executable_path: None,
            target_path: Some(activity.path),
            destination_host: None,
        };

        append_json_line(
            &event,
            policy,
            Some(&assessment),
            ransomware_response.as_ref(),
            containment.as_deref(),
        )
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

        append_json_line(&event, policy, None, None, None)
    }

    fn append_json_line(
        event: &SecurityEvent,
        policy: Option<&PolicyBundle>,
        ransomware: Option<&RansomwareAssessment>,
        ransomware_response: Option<&RansomwareResponseDecision>,
        containment: Option<&str>,
    ) -> io::Result<()> {
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
                "enforcement": "shadow",
                "ransomware": ransomware,
                "ransomware_response": ransomware_response,
                "containment": containment
            })
        } else {
            serde_json::json!({
                "event": event,
                "policy_version": null,
                "decision": "allow",
                "would_deny": false,
                "enforcement": "telemetry_only",
                "ransomware": ransomware,
                "ransomware_response": ransomware_response,
                "containment": containment
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
        network_state: CapabilityState,
        network_detail: &str,
        file_state: CapabilityState,
        file_detail: &str,
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
            .with_capability("network_enforcement", network_state, network_detail)
            .with_capability("filesystem_telemetry", file_state, file_detail)
            .with_capability(
                "ransomware_detection",
                if file_state == CapabilityState::Active {
                    CapabilityState::Shadow
                } else {
                    CapabilityState::Unavailable
                },
                if file_state == CapabilityState::Active {
                    "unique-path Kernel-File ETW correlation enabled; detection only"
                } else {
                    "Kernel-File path telemetry unavailable; ransomware correlation disabled"
                },
            )
    }

    fn select_network_enforcement(
        policy: &PolicyBundle,
    ) -> std::result::Result<Option<NetworkEnforcementPlan>, String> {
        if policy.mode != EnforcementMode::Enforce {
            return Ok(None);
        }

        let mut network_rules = policy
            .rules
            .iter()
            .filter(|rule| {
                rule.action == DecisionAction::Deny && !rule.destination_hosts.is_empty()
            });

        let Some(rule) = network_rules.next() else {
            return Ok(None);
        };

        if network_rules.next().is_some() {
            return Err(
                "multiple deny network rules are not yet representable by the Windows WFP adapter"
                    .to_string(),
            );
        }

        if rule.destination_hosts.len() != 1 || rule.executable_paths.len() > 1 {
            return Err(
                "network deny rule requires exactly one destination and at most one executable"
                    .to_string(),
            );
        }

        let remote = rule.destination_hosts[0]
            .parse::<Ipv4Addr>()
            .map_err(|_| {
                "network deny destination must currently be an exact IPv4 address".to_string()
            })?;

        Ok(Some(NetworkEnforcementPlan {
            rule_id: rule.id.clone(),
            remote_ipv4: remote.to_string(),
            application_path: rule.executable_paths.first().cloned(),
        }))
    }

    fn configure_network_enforcement(
        policy: Option<&PolicyBundle>,
    ) -> (Option<WfpSession>, CapabilityState, String) {
        let Some(policy) = policy else {
            return (
                None,
                CapabilityState::Unavailable,
                "no verified signed policy; WFP runtime filter not installed".to_string(),
            );
        };

        match select_network_enforcement(policy) {
            Ok(None) => (
                None,
                CapabilityState::Shadow,
                if policy.mode == EnforcementMode::Audit {
                    "policy is audit mode; WFP runtime filter intentionally not installed"
                        .to_string()
                } else {
                    "no supported exact-IPv4 deny network rule configured".to_string()
                },
            ),
            Err(detail) => (None, CapabilityState::Shadow, detail),
            Ok(Some(plan)) => {
                let mut session = match WfpSession::open() {
                    Ok(session) => session,
                    Err(error) => {
                        return (
                            None,
                            CapabilityState::Unavailable,
                            format!("cannot open dynamic WFP session: 0x{error:08x}"),
                        )
                    }
                };

                match session.install_exact_ipv4(
                    &plan.remote_ipv4,
                    plan.application_path.as_deref(),
                ) {
                    Ok(()) => (
                        Some(session),
                        CapabilityState::Active,
                        format!(
                            "dynamic WFP block active for rule={} remote_ipv4={} app_scope={}; stopping the service removes the filter",
                            plan.rule_id,
                            plan.remote_ipv4,
                            plan.application_path.as_deref().unwrap_or("all")
                        ),
                    ),
                    Err(error) => (
                        None,
                        CapabilityState::Unavailable,
                        format!("WFP rule installation failed: 0x{error:08x}"),
                    ),
                }
            }
        }
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
        let policy = verify_signed_policy(&envelope, &POLICY_PUBLIC_KEY).ok()?;
        if !accept_policy_version(policy.version) {
            return None;
        }
        Some(policy)
    }

    fn accept_policy_version(version: u64) -> bool {
        let previous = std::fs::read_to_string(POLICY_VERSION_PATH)
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok());

        if previous.is_some_and(|current| version < current) {
            return false;
        }

        let path = Path::new(POLICY_VERSION_PATH);
        if let Some(parent) = path.parent() {
            if create_dir_all(parent).is_err() {
                return false;
            }
        }

        let highest = previous.map_or(version, |current| current.max(version));
        std::fs::write(path, format!("{highest}\n")).is_ok()
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

    #[cfg(test)]
    mod policy_tests {
        use super::*;

        fn rule_policy(
            mode: EnforcementMode,
            destinations: Vec<&str>,
            executables: Vec<&str>,
        ) -> PolicyBundle {
            PolicyBundle {
                version: 1,
                mode,
                rules: vec![nexus_agent_core::PolicyRule {
                    id: "network-test".into(),
                    category: "network".into(),
                    action: DecisionAction::Deny,
                    executable_paths: executables.into_iter().map(str::to_string).collect(),
                    destination_hosts: destinations.into_iter().map(str::to_string).collect(),
                }],
                ransomware_response: None,
            }
        }

        #[test]
        fn audit_policy_never_builds_wfp_plan() {
            assert_eq!(
                select_network_enforcement(&rule_policy(
                    EnforcementMode::Audit,
                    vec!["203.0.113.10"],
                    vec![],
                ))
                .unwrap(),
                None
            );
        }

        #[test]
        fn exact_ipv4_rule_builds_plan() {
            let plan = select_network_enforcement(&rule_policy(
                EnforcementMode::Enforce,
                vec!["203.0.113.10"],
                vec![r"C:\Test\client.exe"],
            ))
            .unwrap()
            .unwrap();

            assert_eq!(plan.remote_ipv4, "203.0.113.10");
            assert_eq!(plan.application_path.as_deref(), Some(r"C:\Test\client.exe"));
        }

        #[test]
        fn hostname_rule_stays_shadow_only() {
            assert!(select_network_enforcement(&rule_policy(
                EnforcementMode::Enforce,
                vec!["example.com"],
                vec![],
            ))
            .is_err());
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
