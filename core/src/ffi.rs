use crate::{DecisionAction, EventKind, PolicyBundle, SecurityEvent, SignedPolicyEnvelope, verify_signed_policy};
use std::{slice, str};

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NexusDecision {
    Allow = 0,
    Deny = 1,
    Alert = 2,
    Error = 255,
}

#[repr(C)]
pub struct NexusPolicyHandle {
    policy: PolicyBundle,
}

fn bytes<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if ptr.is_null() {
        return if len == 0 { Some(&[]) } else { None };
    }
    Some(unsafe { slice::from_raw_parts(ptr, len) })
}

#[no_mangle]
pub extern "C" fn nexus_policy_from_signed_json(
    envelope_ptr: *const u8,
    envelope_len: usize,
    public_key_ptr: *const u8,
    public_key_len: usize,
) -> *mut NexusPolicyHandle {
    let Some(envelope_bytes) = bytes(envelope_ptr, envelope_len) else {
        return std::ptr::null_mut();
    };
    let Some(public_key) = bytes(public_key_ptr, public_key_len) else {
        return std::ptr::null_mut();
    };

    let Ok(envelope) = serde_json::from_slice::<SignedPolicyEnvelope>(envelope_bytes) else {
        return std::ptr::null_mut();
    };
    let Ok(policy) = verify_signed_policy(&envelope, public_key) else {
        return std::ptr::null_mut();
    };

    Box::into_raw(Box::new(NexusPolicyHandle { policy }))
}

#[no_mangle]
pub extern "C" fn nexus_policy_free(handle: *mut NexusPolicyHandle) {
    if handle.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(handle));
    }
}

#[no_mangle]
pub extern "C" fn nexus_policy_version(handle: *const NexusPolicyHandle) -> u64 {
    if handle.is_null() {
        return 0;
    }
    unsafe { (*handle).policy.version }
}

#[no_mangle]
pub extern "C" fn nexus_policy_evaluate_exec(
    handle: *const NexusPolicyHandle,
    path_ptr: *const u8,
    path_len: usize,
) -> NexusDecision {
    if handle.is_null() {
        return NexusDecision::Error;
    }
    let Some(path_bytes) = bytes(path_ptr, path_len) else {
        return NexusDecision::Error;
    };
    let Ok(path) = str::from_utf8(path_bytes) else {
        return NexusDecision::Error;
    };

    let event = SecurityEvent {
        event_id: "ffi".into(),
        timestamp: String::new(),
        device_id: String::new(),
        kind: EventKind::ProcessExec,
        pid: None,
        parent_pid: None,
        executable_path: Some(path.to_owned()),
        target_path: None,
        destination_host: None,
    };

    match unsafe { &(*handle).policy }.evaluate(&event).action {
        DecisionAction::Allow => NexusDecision::Allow,
        DecisionAction::Deny => NexusDecision::Deny,
        DecisionAction::Alert => NexusDecision::Alert,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
    use ed25519_dalek::{Signer, SigningKey};
    use crate::{DecisionAction, EnforcementMode, PolicyRule};

    #[test]
    fn ffi_loads_verified_policy_and_evaluates_exec() {
        let policy = PolicyBundle {
            version: 11,
            mode: EnforcementMode::Enforce,
            rules: vec![PolicyRule {
                id: "deny-demo".into(),
                category: "execution".into(),
                action: DecisionAction::Deny,
                executable_paths: vec!["/tmp/deny-me".into()],
                destination_hosts: vec![],
            }],
        };
        let signing_key = SigningKey::from_bytes(&[3u8; 32]);
        let payload = serde_json::to_vec(&policy).unwrap();
        let envelope = SignedPolicyEnvelope {
            algorithm: "Ed25519".into(),
            key_id: "test".into(),
            payload_b64: BASE64.encode(&payload),
            signature_b64: BASE64.encode(signing_key.sign(&payload).to_bytes()),
        };
        let envelope_json = serde_json::to_vec(&envelope).unwrap();
        let key = signing_key.verifying_key();

        let handle = nexus_policy_from_signed_json(
            envelope_json.as_ptr(),
            envelope_json.len(),
            key.as_bytes().as_ptr(),
            key.as_bytes().len(),
        );
        assert!(!handle.is_null());
        assert_eq!(nexus_policy_version(handle), 11);

        let path = b"/tmp/deny-me";
        assert_eq!(
            nexus_policy_evaluate_exec(handle, path.as_ptr(), path.len()),
            NexusDecision::Deny
        );

        nexus_policy_free(handle);
    }

    #[test]
    fn ffi_rejects_invalid_signature() {
        let envelope = br#"{"algorithm":"Ed25519","key_id":"bad","payload_b64":"e30=","signature_b64":"AA=="}"#;
        let key = [0u8; 32];
        let handle = nexus_policy_from_signed_json(
            envelope.as_ptr(),
            envelope.len(),
            key.as_ptr(),
            key.len(),
        );
        assert!(handle.is_null());
    }
}
