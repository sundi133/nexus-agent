use nexus_agent_core::{AgentActionDecision, DecisionAction};
use nexus_agent_runtime::{
    authorize_action, normalize_mcp_action, read_secret_file, LocalAuthorizationTarget,
};
use reqwest::{blocking::Client, Method as UpstreamMethod, Url};
use serde_json::Value;
use std::{
    env,
    io::Read,
    net::SocketAddr,
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};

const MAX_REQUEST_BODY_BYTES: usize = 4 * 1024 * 1024;
const MAX_ACTIVE_REQUESTS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnavailableMode {
    Deny,
    Allow,
}

#[derive(Clone)]
struct Config {
    listen: SocketAddr,
    upstream: Url,
    server_id: String,
    device_id: String,
    token: String,
    target: LocalAuthorizationTarget,
    unavailable_mode: UnavailableMode,
    upstream_bearer: Option<String>,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("nexus-mcp-http-proxy: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let config = Arc::new(parse_args()?);
    let server = Server::http(config.listen)
        .map_err(|error| format!("cannot bind HTTP proxy: {error}"))?;
    let client = Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(24 * 60 * 60))
        .build()
        .map_err(|error| format!("cannot initialize upstream HTTP client: {error}"))?;

    eprintln!(
        "nexus-mcp-http-proxy: listening={} upstream={}",
        config.listen, config.upstream
    );

    let active = Arc::new(AtomicUsize::new(0));

    for request in server.incoming_requests() {
        if active.fetch_add(1, Ordering::AcqRel) >= MAX_ACTIVE_REQUESTS {
            active.fetch_sub(1, Ordering::AcqRel);
            let _ = request.respond(
                Response::from_string("too many active proxy requests")
                    .with_status_code(StatusCode(503)),
            );
            continue;
        }

        let config = config.clone();
        let client = client.clone();
        let active = active.clone();

        thread::spawn(move || {
            if let Err(error) = handle_request(request, &config, &client) {
                eprintln!("nexus-mcp-http-proxy: request failed: {error}");
            }
            active.fetch_sub(1, Ordering::AcqRel);
        });
    }

    Ok(())
}

fn handle_request(
    mut request: Request,
    config: &Config,
    client: &Client,
) -> Result<(), String> {
    if request.url().split('?').next() != Some("/mcp") {
        request
            .respond(Response::from_string("not found").with_status_code(StatusCode(404)))
            .map_err(|error| format!("cannot write 404 response: {error}"))?;
        return Ok(());
    }

    let upstream_method = match request.method() {
        Method::Post => UpstreamMethod::POST,
        Method::Get => UpstreamMethod::GET,
        Method::Delete => UpstreamMethod::DELETE,
        Method::Options => UpstreamMethod::OPTIONS,
        _ => {
            request
                .respond(
                    Response::from_string("method not allowed")
                        .with_status_code(StatusCode(405)),
                )
                .map_err(|error| format!("cannot write 405 response: {error}"))?;
            return Ok(());
        }
    };

    let body = if request.method() == &Method::Post {
        read_bounded_body(&mut request)?
    } else {
        Vec::new()
    };

    if request.method() == &Method::Post && !body.is_empty() {
        if let Ok(value) = serde_json::from_slice::<Value>(&body) {
            match authorize_jsonrpc_payload(config, &value) {
                AuthorizationOutcome::Allowed => {}
                AuthorizationOutcome::Denied { id, decision } => {
                    return respond_policy_denial(request, id.as_ref(), &decision);
                }
                AuthorizationOutcome::Unavailable { id, detail }
                    if config.unavailable_mode == UnavailableMode::Deny =>
                {
                    return respond_authorization_unavailable(
                        request,
                        id.as_ref(),
                        &detail,
                    );
                }
                AuthorizationOutcome::Unavailable { detail, .. } => {
                    eprintln!(
                        "nexus-mcp-http-proxy: authorization unavailable; fail-open: {detail}"
                    );
                }
            }
        }
    }

    forward_upstream(request, config, client, upstream_method, body)
}

enum AuthorizationOutcome {
    Allowed,
    Denied {
        id: Option<Value>,
        decision: AgentActionDecision,
    },
    Unavailable {
        id: Option<Value>,
        detail: String,
    },
}

fn authorize_jsonrpc_payload(config: &Config, value: &Value) -> AuthorizationOutcome {
    let messages: Vec<&Value> = match value {
        Value::Array(values) => values.iter().collect(),
        _ => vec![value],
    };

    for message in messages {
        let Some(action) =
            normalize_mcp_action(&config.server_id, &config.device_id, message, "mcp-http")
        else {
            continue;
        };

        let id = message.get("id").cloned();
        match authorize_action(&config.target, &config.token, &action) {
            Ok(decision) if decision.action == DecisionAction::Deny => {
                return AuthorizationOutcome::Denied { id, decision };
            }
            Ok(decision) => {
                if decision.action == DecisionAction::Alert {
                    eprintln!(
                        "nexus-mcp-http-proxy: policy alert rule_id={} policy_version={}",
                        decision.rule_id.as_deref().unwrap_or("none"),
                        decision.policy_version
                    );
                }
            }
            Err(error) => {
                return AuthorizationOutcome::Unavailable { id, detail: error };
            }
        }
    }

    AuthorizationOutcome::Allowed
}

fn read_bounded_body(request: &mut Request) -> Result<Vec<u8>, String> {
    if let Some(length) = request.body_length() {
        if length > MAX_REQUEST_BODY_BYTES {
            return Err("MCP request body exceeds 4 MiB".to_string());
        }
    }

    let mut body = Vec::new();
    request
        .as_reader()
        .take((MAX_REQUEST_BODY_BYTES + 1) as u64)
        .read_to_end(&mut body)
        .map_err(|error| format!("cannot read downstream request body: {error}"))?;

    if body.len() > MAX_REQUEST_BODY_BYTES {
        return Err("MCP request body exceeds 4 MiB".to_string());
    }
    Ok(body)
}

fn forward_upstream(
    request: Request,
    config: &Config,
    client: &Client,
    method: UpstreamMethod,
    body: Vec<u8>,
) -> Result<(), String> {
    let mut builder = client.request(method, config.upstream.clone());

    for header in request.headers() {
        let name = header.field.as_str().as_str().to_ascii_lowercase();
        if should_forward_request_header(&name) {
            builder = builder.header(name, header.value.as_str());
        }
    }

    if let Some(token) = config.upstream_bearer.as_deref() {
        builder = builder.bearer_auth(token);
    }

    if !body.is_empty() {
        builder = builder.body(body);
    }

    let upstream = builder
        .send()
        .map_err(|error| format!("upstream request failed: {error}"))?;

    let status = upstream.status().as_u16();
    let content_length = upstream
        .content_length()
        .and_then(|value| usize::try_from(value).ok());

    let mut response_headers = Vec::new();
    for (name, value) in upstream.headers() {
        let lower = name.as_str().to_ascii_lowercase();
        if should_forward_response_header(&lower) {
            if let Ok(value) = value.to_str() {
                if let Ok(header) = Header::from_bytes(name.as_str(), value) {
                    response_headers.push(header);
                }
            }
        }
    }

    let response = Response::new(
        StatusCode(status),
        response_headers,
        upstream,
        content_length,
        None,
    );

    request
        .respond(response)
        .map_err(|error| format!("cannot stream upstream response: {error}"))
}

fn should_forward_request_header(name: &str) -> bool {
    matches!(
        name,
        "accept"
            | "content-type"
            | "mcp-session-id"
            | "last-event-id"
            | "origin"
            | "user-agent"
    )
}

fn should_forward_response_header(name: &str) -> bool {
    matches!(
        name,
        "content-type"
            | "mcp-session-id"
            | "cache-control"
            | "content-encoding"
            | "vary"
    )
}

fn respond_policy_denial(
    request: Request,
    id: Option<&Value>,
    decision: &AgentActionDecision,
) -> Result<(), String> {
    if id.is_none() {
        return request
            .respond(Response::empty(StatusCode(202)))
            .map_err(|error| format!("cannot write denied notification response: {error}"));
    }

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": -32003,
            "message": "Nexus policy denied MCP action",
            "data": {
                "rule_id": decision.rule_id,
                "policy_version": decision.policy_version,
                "would_deny": decision.would_deny
            }
        }
    })
    .to_string();

    let content_type = Header::from_bytes("Content-Type", "application/json")
        .map_err(|_| "cannot build Content-Type header".to_string())?;

    request
        .respond(
            Response::from_string(body)
                .with_status_code(StatusCode(200))
                .with_header(content_type),
        )
        .map_err(|error| format!("cannot write policy denial response: {error}"))
}

fn respond_authorization_unavailable(
    request: Request,
    id: Option<&Value>,
    detail: &str,
) -> Result<(), String> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": -32004,
            "message": "Nexus authorization unavailable",
            "data": {"detail": detail}
        }
    })
    .to_string();

    let content_type = Header::from_bytes("Content-Type", "application/json")
        .map_err(|_| "cannot build Content-Type header".to_string())?;

    request
        .respond(
            Response::from_string(body)
                .with_status_code(StatusCode(503))
                .with_header(content_type),
        )
        .map_err(|error| format!("cannot write unavailable response: {error}"))
}

fn parse_args() -> Result<Config, String> {
    let args: Vec<String> = env::args().skip(1).collect();

    let mut listen = None;
    let mut upstream = None;
    let mut server_id = None;
    let mut device_id = None;
    let mut token_file = None;
    let mut target = None;
    let mut unavailable_mode = UnavailableMode::Deny;
    let mut upstream_bearer_file = None;

    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--listen" => {
                index += 1;
                listen = args.get(index).and_then(|value| value.parse::<SocketAddr>().ok());
            }
            "--upstream" => {
                index += 1;
                upstream = args.get(index).and_then(|value| Url::parse(value).ok());
            }
            "--server-id" => {
                index += 1;
                server_id = args.get(index).cloned();
            }
            "--device-id" => {
                index += 1;
                device_id = args.get(index).cloned();
            }
            "--token-file" => {
                index += 1;
                token_file = args.get(index).map(PathBuf::from);
            }
            "--upstream-bearer-token-file" => {
                index += 1;
                upstream_bearer_file = args.get(index).map(PathBuf::from);
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
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| "missing --pipe name".to_string())?;
                set_target(&mut target, LocalAuthorizationTarget::WindowsPipe(name))?;
            }
            "--on-unavailable" => {
                index += 1;
                unavailable_mode = match args.get(index).map(String::as_str) {
                    Some("deny") => UnavailableMode::Deny,
                    Some("allow") => UnavailableMode::Allow,
                    _ => return Err("--on-unavailable must be deny or allow".to_string()),
                };
            }
            other => return Err(format!("unknown option: {other}")),
        }
        index += 1;
    }

    let listen = listen.ok_or_else(|| "missing/invalid --listen".to_string())?;
    if !listen.ip().is_loopback() {
        return Err("--listen must use a loopback address".to_string());
    }

    let upstream = upstream.ok_or_else(|| "missing/invalid --upstream".to_string())?;
    validate_upstream(&upstream)?;

    let server_id = server_id
        .filter(|value| !value.is_empty() && value.len() <= 256)
        .ok_or_else(|| "missing/invalid --server-id".to_string())?;
    let device_id = device_id
        .filter(|value| !value.is_empty() && value.len() <= 256)
        .ok_or_else(|| "missing/invalid --device-id".to_string())?;
    let token_file = token_file.ok_or_else(|| "missing --token-file".to_string())?;
    let token = read_secret_file(&token_file, 32, 512, true)
        .map_err(|error| format!("invalid local token file: {error:?}"))?;
    let target = target.ok_or_else(|| "missing local Nexus transport".to_string())?;

    let upstream_bearer = match upstream_bearer_file {
        Some(path) => Some(
            read_secret_file(&path, 16, 4096, true)
                .map_err(|error| format!("invalid upstream bearer token file: {error:?}"))?,
        ),
        None => None,
    };

    Ok(Config {
        listen,
        upstream,
        server_id,
        device_id,
        token,
        target,
        unavailable_mode,
        upstream_bearer,
    })
}

fn validate_upstream(url: &Url) -> Result<(), String> {
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return Err("upstream URL may not contain credentials or a fragment".to_string());
    }

    match url.scheme() {
        "https" => Ok(()),
        "http" if upstream_is_loopback(url) => Ok(()),
        _ => Err("upstream must use HTTPS unless it is loopback HTTP".to_string()),
    }
}

fn upstream_is_loopback(url: &Url) -> bool {
    match url.host_str() {
        Some("localhost") => true,
        Some(host) => host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback()),
        None => false,
    }
}

fn set_target(
    slot: &mut Option<LocalAuthorizationTarget>,
    value: LocalAuthorizationTarget,
) -> Result<(), String> {
    if slot.is_some() {
        return Err("select exactly one local Nexus authorization transport".to_string());
    }
    *slot = Some(value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_loopback_listener() {
        assert!("0.0.0.0:9000".parse::<SocketAddr>().unwrap().ip().is_unspecified());
    }

    #[test]
    fn upstream_allows_https_and_loopback_http_only() {
        assert!(validate_upstream(&Url::parse("https://mcp.example/mcp").unwrap()).is_ok());
        assert!(validate_upstream(&Url::parse("http://127.0.0.1:3000/mcp").unwrap()).is_ok());
        assert!(validate_upstream(&Url::parse("http://localhost:3000/mcp").unwrap()).is_ok());
        assert!(validate_upstream(&Url::parse("http://example.com/mcp").unwrap()).is_err());
    }

    #[test]
    fn protected_batch_denies_on_first_denied_action() {
        let value = serde_json::json!([
            {"jsonrpc":"2.0","id":1,"method":"initialize","params":{}},
            {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"delete_file","arguments":{}}}
        ]);

        let messages: Vec<&Value> = match &value {
            Value::Array(values) => values.iter().collect(),
            _ => vec![&value],
        };
        assert_eq!(messages.len(), 2);
        assert!(normalize_mcp_action("fs", "device", messages[0], "test").is_none());
        assert!(normalize_mcp_action("fs", "device", messages[1], "test").is_some());
    }
}
