use crate::{
    plan_ransomware_response, verify_signed_policy, DecisionAction, DetectionConfig, EventKind,
    PolicyBundle, RansomwareResponseAction, RansomwareTracker, SecurityEvent,
    SignedPolicyEnvelope,
};
use std::{slice, str, sync::Mutex};

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

#[repr(C)]
pub struct NexusRansomwareAssessment {
    pub score: u8,
    /// 0=low, 1=medium, 2=high, 3=critical, 255=error.
    pub severity: u8,
}

#[repr(C)]
pub struct NexusRansomwareTrackerHandle {
    tracker: Mutex<RansomwareTracker>,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NexusRansomwareResponse {
    pub matched: bool,
    pub would_enforce: bool,
    pub enforce: bool,
    /// 0=alert, 1=terminate_process, 2=network_isolate,
    /// 3=terminate_and_network_isolate, 255=none/error.
    pub action: u8,
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

#[no_mangle]
pub extern "C" fn nexus_ransomware_tracker_new(
    window_ms: u64,
    max_processes: usize,
) -> *mut NexusRansomwareTrackerHandle {
    if window_ms == 0 || max_processes == 0 {
        return std::ptr::null_mut();
    }

    let tracker = RansomwareTracker::new(DetectionConfig {
        window_ms,
        max_processes,
    });

    Box::into_raw(Box::new(NexusRansomwareTrackerHandle {
        tracker: Mutex::new(tracker),
    }))
}

#[no_mangle]
pub extern "C" fn nexus_ransomware_tracker_free(
    handle: *mut NexusRansomwareTrackerHandle,
) {
    if handle.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(handle));
    }
}

#[no_mangle]
pub extern "C" fn nexus_ransomware_observe_path(
    handle: *mut NexusRansomwareTrackerHandle,
    pid: u32,
    now_ms: u64,
    path_ptr: *const u8,
    path_len: usize,
    renamed: bool,
) -> NexusRansomwareAssessment {
    let error = NexusRansomwareAssessment {
        score: 0,
        severity: 255,
    };

    if handle.is_null() {
        return error;
    }
    let Some(path_bytes) = bytes(path_ptr, path_len) else {
        return error;
    };
    let Ok(path) = str::from_utf8(path_bytes) else {
        return error;
    };

    let handle = unsafe { &*handle };
    let Ok(mut tracker) = handle.tracker.lock() else {
        return error;
    };
    let assessment = tracker.observe_path(pid, now_ms, path, renamed);

    let severity = match assessment.severity.as_str() {
        "low" => 0,
        "medium" => 1,
        "high" => 2,
        "critical" => 3,
        _ => 255,
    };

    NexusRansomwareAssessment {
        score: assessment.score,
        severity,
    }
}

#[no_mangle]
pub extern "C" fn nexus_ransomware_mark_suspicious_process(
    handle: *mut NexusRansomwareTrackerHandle,
    pid: u32,
    now_ms: u64,
) -> bool {
    if handle.is_null() {
        return false;
    }
    let handle = unsafe { &*handle };
    let Ok(mut tracker) = handle.tracker.lock() else {
        return false;
    };
    tracker.mark_suspicious_process(pid, now_ms);
    true
}

#[no_mangle]
pub extern "C" fn nexus_ransomware_plan_response(
    policy_handle: *const NexusPolicyHandle,
    tracker_handle: *mut NexusRansomwareTrackerHandle,
    pid: u32,
    score: u8,
    severity: u8,
) -> NexusRansomwareResponse {
    let none = NexusRansomwareResponse {
        matched: false,
        would_enforce: false,
        enforce: false,
        action: 255,
    };

    if policy_handle.is_null() || tracker_handle.is_null() || severity == 255 {
        return none;
    }

    let tracker_handle = unsafe { &*tracker_handle };
    let Ok(tracker) = tracker_handle.tracker.lock() else {
        return none;
    };
    let Some(features) = tracker.features_for(pid) else {
        return none;
    };

    let assessment = crate::RansomwareAssessment {
        score,
        severity: match severity {
            0 => "low",
            1 => "medium",
            2 => "high",
            3 => "critical",
            _ => return none,
        }
        .to_string(),
        reasons: Vec::new(),
    };

    let policy = unsafe { &(*policy_handle).policy };
    let Some(decision) = plan_ransomware_response(policy, pid, &features, &assessment) else {
        return none;
    };

    let action = match decision.action {
        RansomwareResponseAction::Alert => 0,
        RansomwareResponseAction::TerminateProcess => 1,
        RansomwareResponseAction::NetworkIsolate => 2,
        RansomwareResponseAction::TerminateAndNetworkIsolate => 3,
    };

    NexusRansomwareResponse {
        matched: decision.matched,
        would_enforce: decision.would_enforce,
        enforce: decision.enforce,
        action,
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
            ransomware_response: None,
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
    fn ffi_ransomware_tracker_deduplicates_paths() {
        let handle = nexus_ransomware_tracker_new(10_000, 16);
        assert!(!handle.is_null());

        let path = b"/tmp/a";
        for now in 0..100 {
            let assessment = nexus_ransomware_observe_path(
                handle,
                99,
                now,
                path.as_ptr(),
                path.len(),
                false,
            );
            assert_eq!(assessment.severity, 0);
        }

        nexus_ransomware_tracker_free(handle);
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
