#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("fanotify-shadow is only supported on Linux");
}

#[cfg(target_os = "linux")]
fn main() -> std::io::Result<()> {
    linux_shadow::run()
}

#[cfg(target_os = "linux")]
mod linux_shadow {
    use nexus_agent_core::{
        verify_signed_policy, EventKind, PolicyBundle, SecurityEvent, SignedPolicyEnvelope,
    };
    use std::{
        ffi::CString,
        io,
        mem::size_of,
        os::fd::RawFd,
        path::PathBuf,
        time::Instant,
    };

    const BUFFER_SIZE: usize = 64 * 1024;
    const POLICY_PATH: &str = "/var/lib/votal/nexus/policy.signed.json";
    const POLICY_PUBLIC_KEY: [u8; 32] = [0; 32];

    pub fn run() -> io::Result<()> {
        let fan_fd = start("/")?;
        let policy = load_verified_policy();
        eprintln!(
            "nexus-fanotify-shadow: FAN_OPEN_EXEC_PERM active; every decision is FAN_ALLOW; policy_loaded={}",
            policy.is_some()
        );

        let mut buffer = vec![0u8; BUFFER_SIZE];

        loop {
            let read_count = unsafe {
                libc::read(fan_fd, buffer.as_mut_ptr().cast(), buffer.len())
            };

            if read_count < 0 {
                let error = io::Error::last_os_error();
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
                let started = Instant::now();

                // Shadow-mode invariant: permission is granted before telemetry work.
                let response = libc::fanotify_response {
                    fd: metadata.fd,
                    response: libc::FAN_ALLOW,
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

                let path = fd_path(metadata.fd).unwrap_or_else(|| "<unknown>".to_string());
                let would_deny = policy
                    .map(|policy| {
                        let event = SecurityEvent {
                            event_id: "linux-shadow".to_string(),
                            timestamp: String::new(),
                            device_id: String::new(),
                            kind: EventKind::ProcessExec,
                            pid: Some(metadata.pid as u32),
                            parent_pid: None,
                            executable_path: Some(path.clone()),
                            target_path: None,
                            destination_host: None,
                        };
                        policy.evaluate(&event).would_deny
                    })
                    .unwrap_or(false);
                eprintln!(
                    "nexus-fanotify-shadow: pid={} target={} would_deny={} action=allow response_latency_us={}",
                    metadata.pid, path, would_deny, latency_us
                );
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
        #[test]
        fn response_layout_matches_kernel_contract() {
            assert_eq!(
                std::mem::size_of::<libc::fanotify_response>(),
                std::mem::size_of::<i32>() + std::mem::size_of::<u32>()
            );
        }
    }
}
