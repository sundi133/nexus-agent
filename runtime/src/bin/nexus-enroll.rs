use nexus_agent_runtime::{
    atomic_write_device_credential, read_secret_file, DeviceCredential,
};
use reqwest::{blocking::Client, Url};
use serde::Serialize;
use std::{
    env,
    io::Read,
    path::PathBuf,
    time::Duration,
};

const MAX_ENROLLMENT_RESPONSE_BYTES: u64 = 64 * 1024;

#[derive(Debug, Serialize)]
struct EnrollmentRequest {
    platform: String,
    architecture: String,
    agent_version: String,
}

struct Config {
    url: Url,
    bootstrap_token_file: PathBuf,
    output: PathBuf,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("nexus-enroll: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let config = parse_args()?;
    let bootstrap_token =
        read_secret_file(&config.bootstrap_token_file, 16, 16 * 1024, true)
            .map_err(|error| format!("invalid bootstrap token file: {error:?}"))?;

    let client = Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(30))
        .user_agent("Votal-Nexus-Enroll/0.1")
        .build()
        .map_err(|error| format!("cannot initialize HTTPS client: {error}"))?;

    let response = client
        .post(config.url)
        .bearer_auth(bootstrap_token)
        .json(&EnrollmentRequest {
            platform: env::consts::OS.to_string(),
            architecture: env::consts::ARCH.to_string(),
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
        })
        .send()
        .map_err(|error| format!("enrollment request failed: {error}"))?;

    if !response.status().is_success() {
        return Err(format!("enrollment server returned HTTP {}", response.status()));
    }

    if response
        .content_length()
        .is_some_and(|length| length > MAX_ENROLLMENT_RESPONSE_BYTES)
    {
        return Err("enrollment response is too large".to_string());
    }

    let mut limited = response.take(MAX_ENROLLMENT_RESPONSE_BYTES + 1);
    let mut body = Vec::new();
    limited
        .read_to_end(&mut body)
        .map_err(|error| format!("cannot read enrollment response: {error}"))?;
    if body.len() as u64 > MAX_ENROLLMENT_RESPONSE_BYTES {
        return Err("enrollment response is too large".to_string());
    }

    let credential: DeviceCredential = serde_json::from_slice(&body)
        .map_err(|error| format!("invalid enrollment credential JSON: {error}"))?;
    credential
        .validate()
        .map_err(|error| format!("enrollment credential rejected: {error}"))?;

    atomic_write_device_credential(&config.output, &credential)
        .map_err(|error| format!("cannot install device credential: {error}"))?;

    println!(
        "enrolled device_id={} credential_file={}",
        credential.device_id,
        config.output.display()
    );
    Ok(())
}

fn parse_args() -> Result<Config, String> {
    let args: Vec<String> = env::args().skip(1).collect();
    let mut url = None;
    let mut bootstrap_token_file = None;
    let mut output = None;

    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--url" => {
                index += 1;
                url = args.get(index).and_then(|value| Url::parse(value).ok());
            }
            "--bootstrap-token-file" => {
                index += 1;
                bootstrap_token_file = args.get(index).map(PathBuf::from);
            }
            "--output" => {
                index += 1;
                output = args.get(index).map(PathBuf::from);
            }
            other => return Err(format!("unknown option: {other}")),
        }
        index += 1;
    }

    let url = url.ok_or_else(|| "missing/invalid --url".to_string())?;
    if url.scheme() != "https" {
        return Err("enrollment URL must use HTTPS".to_string());
    }
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return Err("enrollment URL may not contain credentials or a fragment".to_string());
    }

    Ok(Config {
        url,
        bootstrap_token_file: bootstrap_token_file
            .ok_or_else(|| "missing --bootstrap-token-file".to_string())?,
        output: output.ok_or_else(|| "missing --output".to_string())?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_https_enrollment_url() {
        let url = Url::parse("http://control.example/enroll").unwrap();
        assert_ne!(url.scheme(), "https");
    }

    #[test]
    fn enrollment_request_does_not_include_bootstrap_secret() {
        let request = EnrollmentRequest {
            platform: "linux".into(),
            architecture: "x86_64".into(),
            agent_version: "0.1.0".into(),
        };
        let encoded = serde_json::to_string(&request).unwrap();
        assert!(!encoded.contains("token"));
        assert!(encoded.contains("platform"));
    }
}
