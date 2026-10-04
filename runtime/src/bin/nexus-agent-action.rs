use nexus_agent_core::{AgentActionEvent, DecisionAction};
use nexus_agent_runtime::{
    authorize_action, read_secret_file, LocalAuthorizationTarget,
};
use std::{env, fs, path::PathBuf, process};

fn main() {
    match run() {
        Ok(decision) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&decision).expect("decision serializes")
            );
            match decision.action {
                DecisionAction::Allow => {}
                DecisionAction::Alert => process::exit(10),
                DecisionAction::Deny => process::exit(20),
            }
        }
        Err(error) => {
            eprintln!("nexus-agent-action: {error}");
            process::exit(1);
        }
    }
}

fn run() -> Result<nexus_agent_core::AgentActionDecision, String> {
    let args: Vec<String> = env::args().skip(1).collect();
    let mut event_path = None;
    let mut token_path = None;
    let mut target = None;
    let mut index = 0usize;

    while index < args.len() {
        match args[index].as_str() {
            "--event" => {
                index += 1;
                event_path = args.get(index).map(PathBuf::from);
            }
            "--token-file" => {
                index += 1;
                token_path = args.get(index).map(PathBuf::from);
            }
            "--tcp" => {
                index += 1;
                let port = args
                    .get(index)
                    .and_then(|value| value.parse::<u16>().ok())
                    .filter(|port| *port >= 1024)
                    .ok_or_else(|| "invalid --tcp port".to_string())?;
                set_target(&mut target, LocalAuthorizationTarget::Tcp(port))?;
            }
            #[cfg(unix)]
            "--unix" => {
                index += 1;
                let path = args
                    .get(index)
                    .map(PathBuf::from)
                    .ok_or_else(|| "missing --unix path".to_string())?;
                set_target(&mut target, LocalAuthorizationTarget::Unix(path))?;
            }
            #[cfg(windows)]
            "--pipe" => {
                index += 1;
                let name = args
                    .get(index)
                    .cloned()
                    .filter(|value| !value.trim().is_empty())
                    .ok_or_else(|| "missing --pipe name".to_string())?;
                set_target(
                    &mut target,
                    LocalAuthorizationTarget::WindowsPipe(name),
                )?;
            }
            other => return Err(format!("unknown argument: {other}")),
        }
        index += 1;
    }

    let event_path = event_path.ok_or_else(|| "missing --event".to_string())?;
    let token_path = token_path.ok_or_else(|| "missing --token-file".to_string())?;
    let target = target.ok_or_else(|| "missing transport selector".to_string())?;

    let event_bytes =
        fs::read(&event_path).map_err(|error| format!("cannot read event: {error}"))?;
    let event: AgentActionEvent = serde_json::from_slice(&event_bytes)
        .map_err(|error| format!("invalid event JSON: {error}"))?;
    let token = read_secret_file(&token_path, 32, 512, true)
        .map_err(|error| format!("invalid token file: {error:?}"))?;

    authorize_action(&target, &token, &event)
}

fn set_target(
    slot: &mut Option<LocalAuthorizationTarget>,
    value: LocalAuthorizationTarget,
) -> Result<(), String> {
    if slot.is_some() {
        return Err("select exactly one local transport".to_string());
    }
    *slot = Some(value);
    Ok(())
}
