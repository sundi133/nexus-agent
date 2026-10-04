use nexus_agent_core::{PolicyBundle, SecurityEvent};
use std::{env, fs, process};

fn usage() -> ! {
    eprintln!("Usage: nexus-agent-core evaluate <policy.json> <event.json>");
    process::exit(2);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 || args[1] != "evaluate" {
        usage();
    }

    let policy_text = fs::read_to_string(&args[2]).unwrap_or_else(|error| {
        eprintln!("cannot read policy {}: {error}", args[2]);
        process::exit(2);
    });
    let event_text = fs::read_to_string(&args[3]).unwrap_or_else(|error| {
        eprintln!("cannot read event {}: {error}", args[3]);
        process::exit(2);
    });

    let policy: PolicyBundle = serde_json::from_str(&policy_text).unwrap_or_else(|error| {
        eprintln!("invalid policy JSON: {error}");
        process::exit(2);
    });
    let event: SecurityEvent = serde_json::from_str(&event_text).unwrap_or_else(|error| {
        eprintln!("invalid event JSON: {error}");
        process::exit(2);
    });

    let decision = policy.evaluate(&event);
    println!("{}", serde_json::to_string_pretty(&decision).expect("decision serializes"));
}
