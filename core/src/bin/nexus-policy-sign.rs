use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use nexus_agent_core::{PolicyBundle, SignedPolicyEnvelope};
use std::{env, fs, process};

fn fail(message: impl AsRef<str>) -> ! {
    eprintln!("nexus-policy-sign: {}", message.as_ref());
    process::exit(2);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        fail("usage: nexus-policy-sign <key-id> <policy.json> <output.signed.json>");
    }

    let key_b64 = env::var("NEXUS_POLICY_SIGNING_KEY_B64")
        .unwrap_or_else(|_| fail("NEXUS_POLICY_SIGNING_KEY_B64 is required"));
    let key_bytes = BASE64
        .decode(key_b64.trim())
        .unwrap_or_else(|_| fail("signing key must be base64"));
    let key_array: [u8; 32] = key_bytes
        .try_into()
        .unwrap_or_else(|_| fail("signing key must decode to exactly 32 bytes"));
    let signing_key = SigningKey::from_bytes(&key_array);

    let policy_text = fs::read_to_string(&args[2])
        .unwrap_or_else(|error| fail(format!("cannot read policy: {error}")));
    let policy: PolicyBundle = serde_json::from_str(&policy_text)
        .unwrap_or_else(|error| fail(format!("invalid policy JSON: {error}")));

    // Re-serialize the typed policy so signatures do not depend on whitespace.
    let payload = serde_json::to_vec(&policy)
        .unwrap_or_else(|error| fail(format!("cannot serialize policy: {error}")));
    let signature = signing_key.sign(&payload);

    let envelope = SignedPolicyEnvelope {
        algorithm: "Ed25519".to_string(),
        key_id: args[1].clone(),
        payload_b64: BASE64.encode(&payload),
        signature_b64: BASE64.encode(signature.to_bytes()),
    };

    let output = serde_json::to_vec_pretty(&envelope)
        .unwrap_or_else(|error| fail(format!("cannot serialize envelope: {error}")));
    fs::write(&args[3], output)
        .unwrap_or_else(|error| fail(format!("cannot write output: {error}")));

    println!(
        "signed policy version={} key_id={} public_key_b64={}",
        policy.version,
        envelope.key_id,
        BASE64.encode(signing_key.verifying_key().as_bytes())
    );
}
