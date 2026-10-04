use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use nexus_agent_core::{AgentHealth, CapabilityState};
use nexus_agent_runtime::{
    DiskSpool, HttpControlPlane, JsonlTailer, PolicyStore, RuntimeConfig, RuntimeWorker,
};
use std::{
    env, fs, io,
    path::Path,
    sync::mpsc,
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
const WINDOWS_CONFIG_PATH: &str = r"C:\ProgramData\Votal\Nexus\runtime.json";

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

        let health = read_health(&config.health_source_path);
        let report = worker.run_once(&health);
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
