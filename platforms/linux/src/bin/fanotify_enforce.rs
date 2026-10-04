#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("fanotify-enforce is only supported on Linux");
}

#[cfg(target_os = "linux")]
fn main() -> std::io::Result<()> {
    linux_enforce::run()
}

#[cfg(target_os = "linux")]
mod linux_enforce {
    use nexus_agent_core::{
        verify_signed_policy, DecisionAction, EventKind, PolicyBundle, SecurityEvent,
        SignedPolicyEnvelope,
    };
    use std::{
        ffi::CString,
        io,
        mem::size_of,
        os::fd::RawFd,
        path::PathBuf,
        sync::atomic::{AtomicBool, Ordering},
        time::Instant,
    };

    const BUFFER_SIZE: usize = 64 * 1024;
    const POLICY_PATH: &str = "/var/lib/votal/nexus/policy.signed.json";
    // Development placeholder. Production builds must pin the real Ed25519 public key.
    const POLICY_PUBLIC_KEY: [u8; 32] = [0; 32];

    static KILL_SWITCH: AtomicBool = AtomicBool::new(false);

    extern "C" fn kill_switch_on(_signal: libc::c_int) {
        KILL_SWITCH.store(true, Ordering::Relaxed);
    }

    extern "C" fn kill_switch_off(_signal: libc::c_int) {
        KILL_SWITCH.store(false, Ordering::Relaxed);
    }

    pub fn run() -> io::Result<()> {
        unsafe {
            libc::signal(libc::SIGUSR1, kill_switch_on as libc::sighandler_t);
            libc::signal(libc::SIGUSR2, kill_switch_off as libc::sighandler_t);
        }

        let policy = load_verified_policy();
        let fan_fd = start("/")?;

        eprintln!(
            "nexus-fanotify-enforce: active policy_loaded={} SIGUSR1=allow-all SIGUSR2=resume",
            policy.is_some()
        );

        let mut buffer = vec![0u8; BUFFER_SIZE];

        loop {
            let read_count =
                unsafe { libc::read(fan_fd, buffer.as_mut_ptr().cast(), buffer.len()) };

            if read_count < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                unsafe { libc::close(fan_fd) };
                return Err(error);
            }
            if read_count == 0 {
                continue;
            }

            process_events(fan_fd, &buffer[..read_count as usize], policy.as_ref())?;
        }
    }

    fn start(path: &str) -> io::Result<RawFd> {
        let fan_fd = unsafe {
            libc::fanotify_init(
                libc::FAN_CLASS_CONTENT | libc::FAN_CLOEXEC,
                (libc::O_RDONLY | libc::O_LARGEFILE | libc::O_CLOEXEC) as u32,
            )
        };
        if fan_fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let path = CString::new(path)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid fanotify path"))?;

        let result = unsafe {
            libc::fanotify_mark(
                fan_fd,
                libc::FAN_MARK_ADD | libc::FAN_MARK_MOUNT,
                libc::FAN_OPEN_EXEC_PERM | libc::FAN_EVENT_ON_CHILD,
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

    fn process_events(
        fan_fd: RawFd,
        buffer: &[u8],
        policy: Option<&PolicyBundle>,
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

            if metadata.fd >= 0 && metadata.mask & libc::FAN_OPEN_EXEC_PERM != 0 {
                handle_exec_permission(fan_fd, metadata, policy)?;
            }

            let event_len = metadata.event_len as usize;
            if event_len > buffer.len().saturating_sub(offset) {
                break;
            }
            offset += event_len;
        }

        Ok(())
    }

    fn handle_exec_permission(
        fan_fd: RawFd,
        metadata: &libc::fanotify_event_metadata,
        policy: Option<&PolicyBundle>,
    ) -> io::Result<()> {
        let started = Instant::now();
        let path = fd_path(metadata.fd);

        let deny = if KILL_SWITCH.load(Ordering::Relaxed) {
            false
        } else {
            match (policy, path.as_deref()) {
                (Some(policy), Some(path)) => {
                    evaluate_exec(policy, metadata.pid as u32, path) == DecisionAction::Deny
                }
                _ => false,
            }
        };

        let response = libc::fanotify_response {
            fd: metadata.fd,
            response: if deny { libc::FAN_DENY } else { libc::FAN_ALLOW },
        };

        let written = unsafe {
            libc::write(
                fan_fd,
                (&response as *const libc::fanotify_response).cast(),
                size_of::<libc::fanotify_response>(),
            )
        };
        let latency_us = started.elapsed().as_micros();

        if written != size_of::<libc::fanotify_response>() as isize {
            let error = io::Error::last_os_error();
            unsafe { libc::close(metadata.fd) };
            return Err(error);
        }

        eprintln!(
            "nexus-fanotify-enforce: pid={} target={} action={} kill_switch={} response_latency_us={}",
            metadata.pid,
            path.as_deref().unwrap_or("<unknown>"),
            if deny { "deny" } else { "allow" },
            KILL_SWITCH.load(Ordering::Relaxed),
            latency_us
        );

        unsafe { libc::close(metadata.fd) };
        Ok(())
    }

    fn evaluate_exec(policy: &PolicyBundle, pid: u32, path: &str) -> DecisionAction {
        let event = SecurityEvent {
            event_id: "linux-enforce".to_string(),
            timestamp: String::new(),
            device_id: String::new(),
            kind: EventKind::ProcessExec,
            pid: Some(pid),
            parent_pid: None,
            executable_path: Some(path.to_string()),
            target_path: None,
            destination_host: None,
        };
        policy.evaluate(&event).action
    }

    fn load_verified_policy() -> Option<PolicyBundle> {
        if POLICY_PUBLIC_KEY.iter().all(|byte| *byte == 0) {
            return None;
        }
        let envelope_bytes = std::fs::read(POLICY_PATH).ok()?;
        let envelope: SignedPolicyEnvelope = serde_json::from_slice(&envelope_bytes).ok()?;
        verify_signed_policy(&envelope, &POLICY_PUBLIC_KEY).ok()
    }

    fn fd_path(fd: RawFd) -> Option<String> {
        let link = PathBuf::from(format!("/proc/self/fd/{fd}"));
        std::fs::read_link(link)
            .ok()
            .map(|path| path.to_string_lossy().into_owned())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use nexus_agent_core::{EnforcementMode, PolicyRule};

        fn policy(mode: EnforcementMode) -> PolicyBundle {
            PolicyBundle {
                version: 1,
                mode,
                rules: vec![PolicyRule {
                    id: "test-deny".into(),
                    category: "execution".into(),
                    action: DecisionAction::Deny,
                    executable_paths: vec!["/tmp/nexus-deny-test".into()],
                    destination_hosts: vec![],
                }],
            }
        }

        #[test]
        fn audit_policy_never_denies() {
            assert_ne!(
                evaluate_exec(&policy(EnforcementMode::Audit), 1, "/tmp/nexus-deny-test"),
                DecisionAction::Deny
            );
        }

        #[test]
        fn enforce_policy_denies_exact_test_path() {
            assert_eq!(
                evaluate_exec(&policy(EnforcementMode::Enforce), 1, "/tmp/nexus-deny-test"),
                DecisionAction::Deny
            );
        }

        #[test]
        fn unrelated_path_is_allowed() {
            assert_eq!(
                evaluate_exec(&policy(EnforcementMode::Enforce), 1, "/usr/bin/true"),
                DecisionAction::Allow
            );
        }
    }
}
