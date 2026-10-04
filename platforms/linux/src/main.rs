#[cfg(target_os = "linux")]
mod network;

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("nexus-agent-linux is only supported on Linux");
}

#[cfg(target_os = "linux")]
mod linux_agent {
    use crate::network::{select_network_plan, NftLease};
    use nexus_agent_core::{
        plan_ransomware_response, verify_signed_policy, AgentHealth, CapabilityState,
        DetectionConfig, EventKind, PolicyBundle, RansomwareAssessment,
        RansomwareResponseDecision, RansomwareTracker, SecurityEvent, SignedPolicyEnvelope,
    };
    use std::{
        ffi::CString,
        fs::{read_link, OpenOptions},
        io::{self, Write},
        mem::size_of,
        os::fd::RawFd,
        path::PathBuf,
        time::{Duration, Instant},
    };
    use time::{format_description::well_known::Rfc3339, OffsetDateTime};

    const EVENT_LOG_PATH: &str = "/var/lib/votal/nexus/events.jsonl";
    const BUFFER_SIZE: usize = 64 * 1024;
    const POLICY_PATH: &str = "/var/lib/votal/nexus/policy.signed.json";
    const POLICY_VERSION_PATH: &str = "/var/lib/votal/nexus/policy.version";
    const HEALTH_PATH: &str = "/var/lib/votal/nexus/health.json";
    // Development placeholder. Replace with Votal's pinned 32-byte Ed25519 public key.
    const POLICY_PUBLIC_KEY: [u8; 32] = [0; 32];

    pub fn run() -> io::Result<()> {
        let fan_fd = fanotify_start("/")?;
        let policy = load_verified_policy();
        let (mut network_lease, mut network_state, mut network_detail) =
            configure_network_enforcement(policy.as_ref());

        eprintln!(
            "nexus-agent-linux: fanotify audit collector active on /; policy_loaded={}; network_state={:?}",
            policy.is_some(),
            network_state,
        );
        let _ = write_health(&build_health(
            policy.as_ref(),
            network_state,
            &network_detail,
        ));

        let started = Instant::now();
        let mut ransomware_tracker = RansomwareTracker::new(DetectionConfig::default());
        let mut buffer = vec![0u8; BUFFER_SIZE];

        loop {
            let refresh_error = network_lease
                .as_mut()
                .and_then(|lease| lease.refresh_if_due().err());

            if let Some(error) = refresh_error {
                network_lease.take();
                network_state = CapabilityState::Unavailable;
                network_detail = format!("nftables lease refresh failed: {error}");
                let _ = write_health(&build_health(
                    policy.as_ref(),
                    network_state,
                    &network_detail,
                ));
            }

            let read_count = unsafe {
                libc::read(
                    fan_fd,
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                )
            };

            if read_count < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::WouldBlock {
                    std::thread::sleep(Duration::from_millis(50));
                    continue;
                }
                unsafe { libc::close(fan_fd) };
                return Err(error);
            }

            if read_count == 0 {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }

            parse_events(
                &buffer[..read_count as usize],
                policy.as_ref(),
                &mut ransomware_tracker,
                started.elapsed().as_millis().min(u64::MAX as u128) as u64,
            )?;
        }
    }

    fn fanotify_start(path: &str) -> io::Result<RawFd> {
        let fan_fd = unsafe {
            libc::fanotify_init(
                libc::FAN_CLASS_NOTIF | libc::FAN_CLOEXEC | libc::FAN_NONBLOCK,
                (libc::O_RDONLY | libc::O_LARGEFILE | libc::O_CLOEXEC) as u32,
            )
        };
        if fan_fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let path = CString::new(path)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid fanotify path"))?;

        let mask =
            libc::FAN_OPEN_EXEC | libc::FAN_CLOSE_WRITE | libc::FAN_EVENT_ON_CHILD;

        let result = unsafe {
            libc::fanotify_mark(
                fan_fd,
                libc::FAN_MARK_ADD | libc::FAN_MARK_MOUNT,
                mask,
                libc::AT_FDCWD,
                path.as_ptr(),
            )
        };

        if result < 0 {
            let error = io::Error::last_os_error();
            unsafe { libc::close(fan_fd) };
            return Err(error);
        }

        Ok(fan_fd)
    }

    fn parse_events(
        buffer: &[u8],
        policy: Option<&PolicyBundle>,
        ransomware_tracker: &mut RansomwareTracker,
        now_ms: u64,
    ) -> io::Result<()> {
        let mut offset = 0usize;

        while offset + size_of::<libc::fanotify_event_metadata>() <= buffer.len() {
            let metadata = unsafe {
                &*(buffer.as_ptr().add(offset) as *const libc::fanotify_event_metadata)
            };

            if metadata.event_len == 0 {
                break;
            }

            if metadata.vers != libc::FANOTIFY_METADATA_VERSION {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "fanotify metadata version mismatch",
                ));
            }

            if metadata.fd >= 0 {
                let target_path = fd_path(metadata.fd);
                let kind = if metadata.mask & libc::FAN_OPEN_EXEC != 0 {
                    Some(EventKind::ProcessExec)
                } else if metadata.mask & libc::FAN_CLOSE_WRITE != 0 {
                    Some(EventKind::FileWrite)
                } else {
                    None
                };

                if let Some(kind) = kind {
                    let pid = metadata.pid as u32;

                    if matches!(kind, EventKind::ProcessExec) {
                        if let (Some(policy), Some(path)) = (policy, target_path.as_deref()) {
                            let exec_event = SecurityEvent {
                                event_id: "linux-exec-context".into(),
                                timestamp: String::new(),
                                device_id: String::new(),
                                kind: EventKind::ProcessExec,
                                pid: Some(pid),
                                parent_pid: None,
                                executable_path: Some(path.to_string()),
                                target_path: None,
                                destination_host: None,
                            };
                            if policy.evaluate(&exec_event).would_deny {
                                ransomware_tracker.mark_suspicious_process(pid, now_ms);
                            }
                        }
                    }

                    let ransomware = if matches!(kind, EventKind::FileWrite) {
                        target_path.as_deref().map(|path| {
                            ransomware_tracker.observe_path(
                                pid,
                                now_ms,
                                path,
                                false,
                            )
                        })
                    } else {
                        None
                    };

                    let ransomware_response = match (&ransomware, policy) {
                        (Some(assessment), Some(policy)) => ransomware_tracker
                            .features_for(pid)
                            .and_then(|features| {
                                plan_ransomware_response(policy, pid, &features, assessment)
                            }),
                        _ => None,
                    };

                    let _ = emit_event(
                        pid,
                        kind,
                        target_path,
                        policy,
                        ransomware,
                        ransomware_response,
                    );
                }

                unsafe { libc::close(metadata.fd) };
            }

            let event_len = metadata.event_len as usize;
            if event_len > buffer.len().saturating_sub(offset) {
                break;
            }
            offset += event_len;
        }

        Ok(())
    }


    fn build_health(
        policy: Option<&PolicyBundle>,
        network_state: CapabilityState,
        network_detail: &str,
    ) -> AgentHealth {
        let policy_version = policy.map(|policy| policy.version);
        AgentHealth::new("linux", policy_version)
            .with_capability(
                "policy_verification",
                if policy.is_some() {
                    CapabilityState::Active
                } else {
                    CapabilityState::Unavailable
                },
                if policy.is_some() {
                    "Ed25519 signed policy verified"
                } else {
                    "no verified policy loaded"
                },
            )
            .with_capability(
                "filesystem_telemetry",
                CapabilityState::Active,
                "fanotify notification mode: executable-open and close-write",
            )
            .with_capability(
                "ransomware_detection",
                CapabilityState::Shadow,
                "unique-path close-write correlation enabled; detection only, no process termination",
            )
            .with_capability(
                "network_enforcement",
                network_state,
                network_detail,
            )
            .with_capability(
                "execution_policy",
                if policy.is_some() {
                    CapabilityState::Shadow
                } else {
                    CapabilityState::Unavailable
                },
                if policy.is_some() {
                    "policy is evaluated after notification; no denial"
                } else {
                    "no verified policy; execution enforcement unavailable"
                },
            )
    }

    fn configure_network_enforcement(
        policy: Option<&PolicyBundle>,
    ) -> (Option<NftLease>, CapabilityState, String) {
        let Some(policy) = policy else {
            return (
                None,
                CapabilityState::Unavailable,
                "no verified signed policy; nftables runtime rule not installed".to_string(),
            );
        };

        match select_network_plan(policy) {
            Ok(None) => (
                None,
                CapabilityState::Shadow,
                if policy.mode == nexus_agent_core::EnforcementMode::Audit {
                    "policy is audit mode; nftables runtime rule intentionally not installed"
                        .to_string()
                } else {
                    "no supported exact-IPv4 deny network rule configured".to_string()
                },
            ),
            Err(detail) => (None, CapabilityState::Shadow, detail),
            Ok(Some(plan)) => match NftLease::start(plan) {
                Ok(lease) => {
                    let detail = lease.detail();
                    (Some(lease), CapabilityState::Active, detail)
                }
                Err(error) => (
                    None,
                    CapabilityState::Unavailable,
                    format!("cannot activate nftables lease: {error}"),
                ),
            },
        }
    }

    fn write_health(health: &AgentHealth) -> io::Result<()> {
        let path = std::path::Path::new(HEALTH_PATH);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
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

        let path = std::path::Path::new(POLICY_VERSION_PATH);
        if let Some(parent) = path.parent() {
            if std::fs::create_dir_all(parent).is_err() {
                return false;
            }
        }

        let highest = previous.map_or(version, |current| current.max(version));
        std::fs::write(path, format!("{highest}\n")).is_ok()
    }

    fn fd_path(fd: RawFd) -> Option<String> {
        let link = PathBuf::from(format!("/proc/self/fd/{fd}"));
        read_link(link)
            .ok()
            .map(|path| path.to_string_lossy().into_owned())
    }

    fn emit_event(
        pid: u32,
        kind: EventKind,
        path: Option<String>,
        policy: Option<&PolicyBundle>,
        ransomware: Option<RansomwareAssessment>,
        ransomware_response: Option<RansomwareResponseDecision>,
    ) -> io::Result<()> {
        let now = OffsetDateTime::now_utc();
        let timestamp = now
            .format(&Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string());

        let device_id = std::fs::read_to_string("/etc/machine-id")
            .map(|value| value.trim().to_string())
            .unwrap_or_else(|_| "linux-device".to_string());

        let (executable_path, target_path) = match kind {
            EventKind::ProcessExec => (path, None),
            _ => (None, path),
        };

        let event = SecurityEvent {
            event_id: format!("linux-{}-{}", pid, now.unix_timestamp_nanos()),
            timestamp,
            device_id,
            kind,
            pid: Some(pid),
            parent_pid: None,
            executable_path,
            target_path,
            destination_host: None,
        };

        let log_path = std::path::Path::new(EVENT_LOG_PATH);
        if let Some(parent) = log_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)?;
        let record = if let Some(policy) = policy {
            let decision = policy.evaluate(&event);
            serde_json::json!({
                "event": event,
                "policy_version": decision.policy_version,
                "decision": format!("{:?}", decision.action).to_lowercase(),
                "would_deny": decision.would_deny,
                "enforcement": "shadow",
                "ransomware": ransomware,
                "ransomware_response": ransomware_response
            })
        } else {
            serde_json::json!({
                "event": event,
                "policy_version": null,
                "decision": "allow",
                "would_deny": false,
                "enforcement": "telemetry_only",
                "ransomware": ransomware,
                "ransomware_response": ransomware_response
            })
        };
        serde_json::to_writer(&mut file, &record)?;
        file.write_all(b"\n")?;
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        #[test]
        fn fanotify_metadata_layout_is_nonzero() {
            assert!(std::mem::size_of::<libc::fanotify_event_metadata>() > 0);
        }
    }
}

#[cfg(target_os = "linux")]
fn main() -> std::io::Result<()> {
    linux_agent::run()
}
