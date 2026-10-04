use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use nexus_agent_core::{AgentHealth, CapabilityState, PolicyBundle};
use nexus_agent_runtime::{
    spawn_local_ingest, DiskSpool, HttpControlPlane, JsonlTailer, LocalIngestAuth,
    PolicyStore, ProducerCredential, RuntimeConfig, RuntimeWorker, read_secret_file,
};
#[cfg(unix)]
use nexus_agent_runtime::spawn_local_ingest_unix;
#[cfg(windows)]
use nexus_agent_runtime::spawn_local_ingest_windows_pipe;
use std::{
    env, fs, io,
    path::Path,
    sync::{mpsc, Arc, RwLock},
    thread,
    time::Duration,
};

#[cfg(windows)]
use std::ffi::OsString;
#[cfg(windows)]
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};

#[cfg(windows)]
const WINDOWS_SERVICE_NAME: &str = "VotalNexusRuntime";
#[cfg(windows)]
const WINDOWS_CONFIG_PATH: &str = r"C:\Program Files\Votal\Nexus\runtime.json";

fn load_public_key(path: &Path) -> Result<[u8; 32], String> {
    let encoded = fs::read_to_string(path)
        .map_err(|error| format!("cannot read policy public key: {error}"))?;
    let bytes = BASE64
        .decode(encoded.trim())
        .map_err(|_| "policy public key must be base64".to_string())?;
    bytes
        .try_into()
        .map_err(|_| "policy public key must decode to exactly 32 bytes".to_string())
}

fn load_local_ingest_token(path: &Path) -> Result<String, String> {
    read_secret_file(path, 32, 512, true)
        .map_err(|error| format!("invalid local ingest token file: {error:?}"))
}

fn load_bound_producers(
    producers: &[nexus_agent_runtime::config::LocalProducerConfig],
) -> Result<Vec<ProducerCredential>, String> {
    let mut loaded = Vec::with_capacity(producers.len());
    let mut token_values = std::collections::HashSet::new();

    for producer in producers {
        let token = load_local_ingest_token(&producer.token_file)?;
        if !token_values.insert(token.clone()) {
            return Err(format!(
                "duplicate local producer token detected for agent_id={}",
                producer.agent_id
            ));
        }
        loaded.push(ProducerCredential {
            agent_id: producer.agent_id.clone(),
            token,
            expected_uid: producer.expected_uid,
            executable_paths: producer.executable_paths.clone(),
            executable_sha256: producer.executable_sha256.clone(),
        });
    }

    Ok(loaded)
}

fn load_config(path: &Path) -> Result<RuntimeConfig, String> {
    let config_bytes =
        fs::read(path).map_err(|error| format!("cannot read runtime config: {error}"))?;
    let config: RuntimeConfig = serde_json::from_slice(&config_bytes)
        .map_err(|error| format!("invalid runtime config JSON: {error}"))?;
    config
        .validate()
        .map_err(|error| format!("runtime config rejected: {error}"))?;
    Ok(config)
}

fn read_health(path: &Path) -> AgentHealth {
    fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<AgentHealth>(&bytes).ok())
        .unwrap_or_else(|| {
            AgentHealth::new("runtime-sidecar", None).with_capability(
                "platform_health_source",
                CapabilityState::Unavailable,
                "platform health file missing or invalid",
            )
        })
}

fn spool_error_to_io(error: nexus_agent_runtime::spool::SpoolError) -> io::Error {
    io::Error::other(error.to_string())
}

fn run_runtime_loop(
    config_path: &Path,
    shutdown_rx: Option<&mpsc::Receiver<()>>,
) -> Result<(), String> {
    let config = load_config(config_path)?;
    let public_key = load_public_key(&config.policy_public_key_file)?;

    let transport = HttpControlPlane::new(config.control_plane.clone())
        .map_err(|error| format!("cannot initialize control-plane transport: {error}"))?;
    let policy_store = PolicyStore::new(
        config.policy_signed_path.clone(),
        config.policy_watermark_path.clone(),
        public_key,
    );
    let policy_store_for_decisions = policy_store.clone();
    let active_policy: Arc<RwLock<Option<PolicyBundle>>> = Arc::new(RwLock::new(
        policy_store_for_decisions
            .load_active()
            .ok()
            .flatten()
            .map(|active| active.policy),
    ));
    let spool = DiskSpool::open(
        config.spool_dir.clone(),
        config.spool_max_bytes,
        config.segment_max_bytes,
    )
    .map_err(|error| format!("cannot initialize telemetry spool: {error}"))?;

    let mut worker = RuntimeWorker::new(transport, policy_store, spool);
    let tailer = JsonlTailer::new(
        config.event_source_path.clone(),
        config.event_offset_path.clone(),
    );

    let (action_tx, action_rx) = mpsc::channel();
    let (local_ingest_enabled, local_ingest_identity_mode) = match (
        config.local_ingest_port,
        config.local_ingest_socket_path.as_deref(),
        config.local_ingest_pipe_name.as_deref(),
        config.local_ingest_token_file.as_deref(),
        config.local_ingest_producers.as_slice(),
    ) {
        (Some(port), None, None, Some(token_path), []) => {
            let token = load_local_ingest_token(token_path)?;
            spawn_local_ingest(
                port,
                LocalIngestAuth::LegacyToken(token),
                active_policy.clone(),
                action_tx,
            )
            .map_err(|error| format!("cannot start local agent-action ingest: {error}"))?;
            (true, "legacy_shared_token_tcp")
        }
        (Some(port), None, None, None, producers) if !producers.is_empty() => {
            let credentials = load_bound_producers(producers)?;
            spawn_local_ingest(
                port,
                LocalIngestAuth::BoundProducers(credentials),
                active_policy.clone(),
                action_tx,
            )
            .map_err(|error| format!("cannot start bound agent-action ingest: {error}"))?;
            (true, "credential_bound_tcp")
        }
        #[cfg(unix)]
        (None, Some(socket_path), None, None, producers) if !producers.is_empty() => {
            let credentials = load_bound_producers(producers)?;
            spawn_local_ingest_unix(
                socket_path.to_path_buf(),
                LocalIngestAuth::BoundProducers(credentials),
                active_policy.clone(),
                action_tx,
            )
            .map_err(|error| format!("cannot start attested Unix agent-action ingest: {error}"))?;
            (true, "kernel_peer_attested_unix")
        }
        #[cfg(windows)]
        (None, None, Some(pipe_name), None, producers) if !producers.is_empty() => {
            let credentials = load_bound_producers(producers)?;
            spawn_local_ingest_windows_pipe(
                pipe_name.to_string(),
                LocalIngestAuth::BoundProducers(credentials),
                active_policy.clone(),
                action_tx,
            )
            .map_err(|error| format!("cannot start attested Windows named-pipe ingest: {error}"))?;
            (true, "kernel_client_pid_attested_named_pipe")
        }
        (None, None, None, None, []) => (false, "disabled"),
        _ => return Err("local ingest configuration is incomplete or unsupported on this platform".to_string()),
    };

    let mut previous_cycle_errors: Vec<String> = Vec::new();

    loop {
        if shutdown_rx.is_some_and(|receiver| receiver.try_recv().is_ok()) {
            break;
        }

        match tailer.ingest(|record| worker.enqueue(record).map_err(spool_error_to_io)) {
            Ok(stats) if stats.records > 0 || stats.invalid_records > 0 => {
                eprintln!(
                    "nexus-agent-runtime: ingested={} invalid={} bytes_advanced={}",
                    stats.records, stats.invalid_records, stats.bytes_advanced
                );
            }
            Ok(_) => {}
            Err(error) => {
                eprintln!("nexus-agent-runtime: event ingestion failed: {error}");
            }
        }

        let mut agent_actions_ingested = 0usize;
        while agent_actions_ingested < 1024 {
            match action_rx.try_recv() {
                Ok(event) => {
                    if let Err(error) = worker.enqueue(&event) {
                        previous_cycle_errors.push(format!(
                            "agent-action spool failed: {error}"
                        ));
                        break;
                    }
                    agent_actions_ingested += 1;
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    previous_cycle_errors.push(
                        "local agent-action ingest channel disconnected".to_string(),
                    );
                    break;
                }
            }
        }

        let mut health = read_health(&config.health_source_path);
        health = health.with_capability(
            "agent_action_ingest",
            if local_ingest_enabled {
                CapabilityState::Active
            } else {
                CapabilityState::Unavailable
            },
            if local_ingest_enabled {
                format!(
                    "localhost authenticated MCP/agent-action bridge active mode={local_ingest_identity_mode}; ingested_this_cycle={agent_actions_ingested}"
                )
            } else {
                "local MCP/agent-action bridge not configured".to_string()
            },
        );

        let (attestation_state, attestation_detail) =
            match local_ingest_identity_mode {
                "kernel_peer_attested_unix" => (
                    CapabilityState::Active,
                    "Unix-domain socket peer credentials are enforced; Linux also binds PID/executable when available".to_string(),
                ),
                "kernel_client_pid_attested_named_pipe" => (
                    CapabilityState::Active,
                    "Windows named-pipe client PID and executable identity are kernel-derived".to_string(),
                ),
                "credential_bound_tcp" => (
                    CapabilityState::Shadow,
                    "producer token is bound to agent_id, but loopback TCP does not attest the local process".to_string(),
                ),
                "legacy_shared_token_tcp" => (
                    CapabilityState::Unavailable,
                    "legacy shared token authenticates bridge access only; no trusted agent/process identity".to_string(),
                ),
                _ => (
                    CapabilityState::Unavailable,
                    "local producer attestation is not configured".to_string(),
                ),
            };

        health = health.with_capability(
            "agent_action_peer_attestation",
            attestation_state,
            attestation_detail,
        );

        if let Ok(stats) = worker.spool().stats() {
            health = health.with_capability(
                "managed_runtime_spool",
                if stats.dropped_segments > 0 {
                    CapabilityState::Fallback
                } else {
                    CapabilityState::Active
                },
                format!(
                    "bytes={} segments={} dropped_segments={}",
                    stats.bytes, stats.segments, stats.dropped_segments
                ),
            );
        }

        let agent_policy_state = active_policy
            .read()
            .ok()
            .and_then(|guard| {
                guard.as_ref().map(|policy| {
                    if policy.agent_action_rules.is_empty() {
                        (
                            CapabilityState::Unavailable,
                            format!(
                                "verified policy version={} has no agent-action rules",
                                policy.version
                            ),
                        )
                    } else if policy.mode == nexus_agent_core::EnforcementMode::Audit {
                        (
                            CapabilityState::Shadow,
                            format!(
                                "verified policy version={} has {} agent-action rules in audit mode",
                                policy.version,
                                policy.agent_action_rules.len()
                            ),
                        )
                    } else {
                        (
                            CapabilityState::Active,
                            format!(
                                "verified policy version={} has {} enforceable agent-action rules",
                                policy.version,
                                policy.agent_action_rules.len()
                            ),
                        )
                    }
                })
            })
            .unwrap_or((
                CapabilityState::Unavailable,
                "no verified agent-action policy loaded".to_string(),
            ));

        health = health.with_capability(
            "agent_action_authorization",
            agent_policy_state.0,
            agent_policy_state.1,
        );

        health = health.with_capability(
            "managed_runtime_transport",
            if previous_cycle_errors.is_empty() {
                CapabilityState::Active
            } else {
                CapabilityState::Fallback
            },
            if previous_cycle_errors.is_empty() {
                "previous control-plane cycle completed without transport/policy errors".to_string()
            } else {
                format!(
                    "previous cycle errors: {}",
                    previous_cycle_errors.join(" | ")
                )
            },
        );

        let report = worker.run_once(&health);
        let mut next_cycle_errors = report.errors.clone();

        if report.policy_updated {
            match policy_store_for_decisions.load_active() {
                Ok(active) => {
                    if let Ok(mut guard) = active_policy.write() {
                        *guard = active.map(|value| value.policy);
                    } else {
                        next_cycle_errors.push(
                            "active agent-action policy lock unavailable after policy update"
                                .to_string(),
                        );
                    }
                }
                Err(error) => next_cycle_errors.push(format!(
                    "cannot refresh active agent-action policy after update: {error}"
                )),
            }
        }

        previous_cycle_errors = next_cycle_errors;

        if !report.errors.is_empty() {
            eprintln!(
                "nexus-agent-runtime: cycle errors={}",
                report.errors.join(" | ")
            );
        }

        if let Some(receiver) = shutdown_rx {
            match receiver.recv_timeout(Duration::from_millis(config.cycle_interval_ms)) {
                Ok(_) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
        } else {
            thread::sleep(Duration::from_millis(config.cycle_interval_ms));
        }
    }

    Ok(())
}

#[cfg(not(windows))]
fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: nexus-agent-runtime <runtime-config.json>");
        std::process::exit(2);
    }

    if let Err(error) = run_runtime_loop(Path::new(&args[1]), None) {
        eprintln!("nexus-agent-runtime: {error}");
        std::process::exit(1);
    }
}

#[cfg(windows)]
define_windows_service!(ffi_runtime_service_main, runtime_service_main);

#[cfg(windows)]
fn runtime_service_main(_arguments: Vec<OsString>) {
    if let Err(error) = run_windows_service() {
        eprintln!("nexus-agent-runtime: Windows service failed: {error}");
    }
}

#[cfg(windows)]
fn run_windows_service() -> windows_service::Result<()> {
    let (shutdown_tx, shutdown_rx) = mpsc::channel();

    let status_handle = service_control_handler::register(
        WINDOWS_SERVICE_NAME,
        move |control_event| match control_event {
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            ServiceControl::Stop => {
                let _ = shutdown_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        },
    )?;

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    if let Err(error) = run_runtime_loop(Path::new(WINDOWS_CONFIG_PATH), Some(&shutdown_rx)) {
        eprintln!("nexus-agent-runtime: {error}");
    }

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    Ok(())
}

#[cfg(windows)]
fn main() -> windows_service::Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() == 3 && args[1] == "--console" {
        if let Err(error) = run_runtime_loop(Path::new(&args[2]), None) {
            eprintln!("nexus-agent-runtime: {error}");
            std::process::exit(1);
        }
        return Ok(());
    }

    service_dispatcher::start(WINDOWS_SERVICE_NAME, ffi_runtime_service_main)
}
