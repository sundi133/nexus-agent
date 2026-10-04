use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use nexus_agent_core::{AgentHealth, CapabilityState};
use nexus_agent_runtime::{
    DiskSpool, HttpControlPlane, JsonlTailer, PolicyStore, RuntimeConfig, RuntimeWorker,
};
use std::{env, fs, io, process, thread, time::Duration};

fn fail(message: impl AsRef<str>) -> ! {
    eprintln!("nexus-agent-runtime: {}", message.as_ref());
    process::exit(2);
}

fn load_public_key(path: &std::path::Path) -> [u8; 32] {
    let encoded = fs::read_to_string(path)
        .unwrap_or_else(|error| fail(format!("cannot read policy public key: {error}")));
    let bytes = BASE64
        .decode(encoded.trim())
        .unwrap_or_else(|_| fail("policy public key must be base64"));
    bytes
        .try_into()
        .unwrap_or_else(|_| fail("policy public key must decode to exactly 32 bytes"))
}

fn read_health(path: &std::path::Path) -> AgentHealth {
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
    io::Error::new(io::ErrorKind::Other, error.to_string())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        fail("usage: nexus-agent-runtime <runtime-config.json>");
    }

    let config_bytes = fs::read(&args[1])
        .unwrap_or_else(|error| fail(format!("cannot read runtime config: {error}")));
    let config: RuntimeConfig = serde_json::from_slice(&config_bytes)
        .unwrap_or_else(|error| fail(format!("invalid runtime config JSON: {error}")));
    config
        .validate()
        .unwrap_or_else(|error| fail(format!("runtime config rejected: {error}")));

    let public_key = load_public_key(&config.policy_public_key_file);
    let transport = HttpControlPlane::new(config.control_plane.clone())
        .unwrap_or_else(|error| fail(format!("cannot initialize control-plane transport: {error}")));
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
    .unwrap_or_else(|error| fail(format!("cannot initialize telemetry spool: {error}")));

    let mut worker = RuntimeWorker::new(transport, policy_store, spool);
    let tailer = JsonlTailer::new(
        config.event_source_path.clone(),
        config.event_offset_path.clone(),
    );

    loop {
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

        thread::sleep(Duration::from_millis(config.cycle_interval_ms));
    }
}
