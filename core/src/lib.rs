pub mod ffi;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyVersionGuard {
    highest_accepted: Option<u64>,
}

impl PolicyVersionGuard {
    pub fn new(highest_accepted: Option<u64>) -> Self {
        Self { highest_accepted }
    }

    pub fn highest_accepted(&self) -> Option<u64> {
        self.highest_accepted
    }

    pub fn accepts(&self, version: u64) -> bool {
        version > 0 && self.highest_accepted.is_none_or(|current| version >= current)
    }

    pub fn accept(&mut self, version: u64) -> bool {
        if !self.accepts(version) {
            return false;
        }
        self.highest_accepted = Some(
            self.highest_accepted
                .map_or(version, |current| current.max(version)),
        );
        true
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityState {
    Active,
    Shadow,
    Fallback,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityStatus {
    pub name: String,
    pub state: CapabilityState,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentHealth {
    pub schema_version: u32,
    pub platform: String,
    pub policy_version: Option<u64>,
    pub kill_switch_engaged: bool,
    pub capabilities: Vec<CapabilityStatus>,
}

impl AgentHealth {
    pub fn new(platform: impl Into<String>, policy_version: Option<u64>) -> Self {
        Self {
            schema_version: 1,
            platform: platform.into(),
            policy_version,
            kill_switch_engaged: false,
            capabilities: Vec::new(),
        }
    }

    pub fn with_capability(
        mut self,
        name: impl Into<String>,
        state: CapabilityState,
        detail: impl Into<String>,
    ) -> Self {
        self.capabilities.push(CapabilityStatus {
            name: name.into(),
            state,
            detail: detail.into(),
        });
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementMode {
    Audit,
    Enforce,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionAction {
    Allow,
    Deny,
    Alert,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRule {
    pub id: String,
    pub category: String,
    pub action: DecisionAction,
    #[serde(default)]
    pub executable_paths: Vec<String>,
    #[serde(default)]
    pub destination_hosts: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedPolicyEnvelope {
    pub algorithm: String,
    pub key_id: String,
    pub payload_b64: String,
    pub signature_b64: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyVerificationError {
    UnsupportedAlgorithm,
    InvalidPublicKey,
    InvalidPayloadEncoding,
    InvalidSignatureEncoding,
    InvalidSignature,
    InvalidPolicy,
}

pub fn verify_signed_policy(
    envelope: &SignedPolicyEnvelope,
    public_key: &[u8],
) -> Result<PolicyBundle, PolicyVerificationError> {
    if envelope.algorithm != "Ed25519" {
        return Err(PolicyVerificationError::UnsupportedAlgorithm);
    }

    let key_bytes: [u8; 32] = public_key
        .try_into()
        .map_err(|_| PolicyVerificationError::InvalidPublicKey)?;
    let verifying_key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| PolicyVerificationError::InvalidPublicKey)?;

    let payload = BASE64
        .decode(&envelope.payload_b64)
        .map_err(|_| PolicyVerificationError::InvalidPayloadEncoding)?;
    let signature_bytes = BASE64
        .decode(&envelope.signature_b64)
        .map_err(|_| PolicyVerificationError::InvalidSignatureEncoding)?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| PolicyVerificationError::InvalidSignatureEncoding)?;

    verifying_key
        .verify(&payload, &signature)
        .map_err(|_| PolicyVerificationError::InvalidSignature)?;

    let policy: PolicyBundle =
        serde_json::from_slice(&payload).map_err(|_| PolicyVerificationError::InvalidPolicy)?;
    validate_policy(&policy)?;
    Ok(policy)
}

pub fn validate_policy(policy: &PolicyBundle) -> Result<(), PolicyVerificationError> {
    use std::collections::HashSet;

    if policy.version == 0 || policy.rules.len() > 1024 {
        return Err(PolicyVerificationError::InvalidPolicy);
    }

    let mut ids = HashSet::with_capacity(policy.rules.len());

    for rule in &policy.rules {
        if rule.id.is_empty()
            || rule.id.len() > 128
            || rule.category.is_empty()
            || rule.category.len() > 128
            || !ids.insert(rule.id.as_str())
            || (rule.executable_paths.is_empty() && rule.destination_hosts.is_empty())
            || rule.executable_paths.len() > 64
            || rule.destination_hosts.len() > 64
            || rule
                .executable_paths
                .iter()
                .any(|value| value.is_empty() || value.len() > 4096)
            || rule
                .destination_hosts
                .iter()
                .any(|value| value.is_empty() || value.len() > 253)
        {
            return Err(PolicyVerificationError::InvalidPolicy);
        }
    }

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyBundle {
    pub version: u64,
    pub mode: EnforcementMode,
    #[serde(default)]
    pub rules: Vec<PolicyRule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    ProcessExec,
    ProcessFork,
    ProcessExit,
    FileOpen,
    FileWrite,
    FileRename,
    FileDelete,
    FileCreate,
    VolumeMount,
    NetworkFlow,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub event_id: String,
    pub timestamp: String,
    pub device_id: String,
    pub kind: EventKind,
    pub pid: Option<u32>,
    pub parent_pid: Option<u32>,
    pub executable_path: Option<String>,
    pub target_path: Option<String>,
    pub destination_host: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub action: DecisionAction,
    pub rule_id: Option<String>,
    pub reason: String,
    pub policy_version: u64,
    pub would_deny: bool,
}

impl PolicyBundle {
    /// Evaluate an event deterministically. Rules are evaluated in declared order;
    /// deployments should validate and sign bundles before loading them.
    pub fn evaluate(&self, event: &SecurityEvent) -> PolicyDecision {
        for rule in &self.rules {
            let has_path_selector = !rule.executable_paths.is_empty();
            let has_host_selector = !rule.destination_hosts.is_empty();

            // Empty-selector rules are intentionally inert. For populated
            // selector dimensions, every dimension must match. Values within
            // one dimension are alternatives (OR).
            if !has_path_selector && !has_host_selector {
                continue;
            }

            let path_matches = !has_path_selector
                || event.executable_path.as_ref().is_some_and(|path| {
                    rule.executable_paths.iter().any(|candidate| candidate == path)
                });

            let host_matches = !has_host_selector
                || event.destination_host.as_ref().is_some_and(|host| {
                    rule.destination_hosts.iter().any(|candidate| {
                        candidate.eq_ignore_ascii_case(host)
                    })
                });

            if !(path_matches && host_matches) {
                continue;
            }

            let would_deny = rule.action == DecisionAction::Deny;
            let action = match (self.mode, rule.action) {
                (EnforcementMode::Audit, DecisionAction::Deny) => DecisionAction::Alert,
                (_, action) => action,
            };

            return PolicyDecision {
                action,
                rule_id: Some(rule.id.clone()),
                reason: format!("matched policy category: {}", rule.category),
                policy_version: self.version,
                would_deny,
            };
        }

        PolicyDecision {
            action: DecisionAction::Allow,
            rule_id: None,
            reason: "no matching rule".to_string(),
            policy_version: self.version,
            would_deny: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessWindow {
    pub pid: u32,
    pub window_started_ms: u64,
    pub last_event_ms: u64,
    pub unique_paths_modified: u32,
    pub rename_count: u32,
    pub suspicious_process_context: bool,
}

impl ProcessWindow {
    pub fn new(pid: u32, now_ms: u64) -> Self {
        Self {
            pid,
            window_started_ms: now_ms,
            last_event_ms: now_ms,
            unique_paths_modified: 0,
            rename_count: 0,
            suspicious_process_context: false,
        }
    }

    pub fn reset(&mut self, now_ms: u64) {
        self.window_started_ms = now_ms;
        self.last_event_ms = now_ms;
        self.unique_paths_modified = 0;
        self.rename_count = 0;
        self.suspicious_process_context = false;
    }

    pub fn observe_file_change(&mut self, now_ms: u64, renamed: bool) {
        self.last_event_ms = now_ms;
        self.unique_paths_modified = self.unique_paths_modified.saturating_add(1);
        if renamed {
            self.rename_count = self.rename_count.saturating_add(1);
        }
    }

    pub fn features(&self) -> RansomwareFeatures {
        RansomwareFeatures {
            unique_paths_modified: self.unique_paths_modified,
            rename_count: self.rename_count,
            suspicious_process_context: self.suspicious_process_context,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectionConfig {
    pub window_ms: u64,
    pub max_processes: usize,
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            window_ms: 5_000,
            max_processes: 4_096,
        }
    }
}

#[derive(Debug)]
pub struct RansomwareTracker {
    config: DetectionConfig,
    windows: HashMap<u32, ProcessWindow>,
    modified_paths: HashMap<u32, HashSet<String>>,
}

impl RansomwareTracker {
    pub fn new(config: DetectionConfig) -> Self {
        Self {
            config,
            windows: HashMap::new(),
            modified_paths: HashMap::new(),
        }
    }

    fn ensure_capacity_for(&mut self, pid: u32) {
        if !self.windows.contains_key(&pid) && self.windows.len() >= self.config.max_processes {
            if let Some(oldest_pid) = self.windows
                .values()
                .min_by_key(|window| window.last_event_ms)
                .map(|window| window.pid)
            {
                self.windows.remove(&oldest_pid);
                self.modified_paths.remove(&oldest_pid);
            }
        }
    }

    /// Legacy event-count API retained for replay compatibility. Production
    /// filesystem adapters should use observe_path so repeated writes to one
    /// file do not inflate the unique-path signal.
    pub fn observe(&mut self, pid: u32, now_ms: u64, renamed: bool) -> RansomwareAssessment {
        self.expire(now_ms);
        self.ensure_capacity_for(pid);

        let window = self.windows
            .entry(pid)
            .or_insert_with(|| ProcessWindow::new(pid, now_ms));

        if now_ms.saturating_sub(window.window_started_ms) > self.config.window_ms {
            window.reset(now_ms);
            self.modified_paths.remove(&pid);
        }

        window.observe_file_change(now_ms, renamed);
        assess_ransomware(&window.features())
    }

    pub fn observe_path(
        &mut self,
        pid: u32,
        now_ms: u64,
        path: &str,
        renamed: bool,
    ) -> RansomwareAssessment {
        self.expire(now_ms);
        self.ensure_capacity_for(pid);

        let should_reset = self.windows.get(&pid).is_some_and(|window| {
            now_ms.saturating_sub(window.window_started_ms) > self.config.window_ms
        });

        if should_reset {
            if let Some(window) = self.windows.get_mut(&pid) {
                window.reset(now_ms);
            }
            self.modified_paths.remove(&pid);
        }

        self.windows
            .entry(pid)
            .or_insert_with(|| ProcessWindow::new(pid, now_ms));

        let is_new_path = self
            .modified_paths
            .entry(pid)
            .or_default()
            .insert(path.to_string());

        let window = self.windows.get_mut(&pid).expect("window exists");
        window.last_event_ms = now_ms;
        if is_new_path {
            window.unique_paths_modified = window.unique_paths_modified.saturating_add(1);
        }
        if renamed {
            window.rename_count = window.rename_count.saturating_add(1);
        }

        assess_ransomware(&window.features())
    }

    pub fn mark_suspicious_process(&mut self, pid: u32, now_ms: u64) {
        let window = self.windows
            .entry(pid)
            .or_insert_with(|| ProcessWindow::new(pid, now_ms));
        window.suspicious_process_context = true;
        window.last_event_ms = now_ms;
    }

    pub fn expire(&mut self, now_ms: u64) {
        let window_ms = self.config.window_ms;
        let expired: Vec<u32> = self
            .windows
            .iter()
            .filter_map(|(pid, window)| {
                (now_ms.saturating_sub(window.last_event_ms) > window_ms).then_some(*pid)
            })
            .collect();

        for pid in expired {
            self.windows.remove(&pid);
            self.modified_paths.remove(&pid);
        }
    }

    pub fn tracked_processes(&self) -> usize {
        self.windows.len()
    }
}

#[derive(Debug)]
pub struct BoundedEventQueue<T> {
    capacity: usize,
    queue: VecDeque<T>,
    dropped: u64,
}

impl<T> BoundedEventQueue<T> {
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "queue capacity must be non-zero");
        Self {
            capacity,
            queue: VecDeque::with_capacity(capacity),
            dropped: 0,
        }
    }

    /// Non-blocking producer semantics: preserve already queued work and drop
    /// the newest event when full. Native callbacks must never wait on consumers.
    pub fn try_push(&mut self, event: T) -> bool {
        if self.queue.len() >= self.capacity {
            self.dropped = self.dropped.saturating_add(1);
            return false;
        }
        self.queue.push_back(event);
        true
    }

    pub fn pop(&mut self) -> Option<T> {
        self.queue.pop_front()
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    pub fn dropped(&self) -> u64 {
        self.dropped
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RansomwareFeatures {
    pub unique_paths_modified: u32,
    pub rename_count: u32,
    pub suspicious_process_context: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RansomwareAssessment {
    pub score: u8,
    pub severity: String,
    pub reasons: Vec<String>,
}

/// Baseline heuristic for replay tests only. Production thresholds require
/// workload calibration, process baselines, bounded time windows, and false-positive testing.
pub fn assess_ransomware(features: &RansomwareFeatures) -> RansomwareAssessment {
    let mut score: u16 = 0;
    let mut reasons = Vec::new();

    if features.unique_paths_modified >= 100 {
        score += 40;
        reasons.push("high number of unique paths modified".to_string());
    }
    if features.rename_count >= 50 {
        score += 30;
        reasons.push("high file rename rate".to_string());
    }
    if features.suspicious_process_context {
        score += 30;
        reasons.push("suspicious process context".to_string());
    }

    let score = score.min(100) as u8;
    let severity = match score {
        0..=29 => "low",
        30..=59 => "medium",
        60..=79 => "high",
        _ => "critical",
    };

    RansomwareAssessment {
        score,
        severity: severity.to_string(),
        reasons,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn event() -> SecurityEvent {
        SecurityEvent {
            event_id: "evt-1".into(),
            timestamp: "2026-01-01T00:00:00Z".into(),
            device_id: "device-test".into(),
            kind: EventKind::ProcessExec,
            pid: Some(42),
            parent_pid: Some(1),
            executable_path: Some("/tmp/test-malware".into()),
            target_path: None,
            destination_host: None,
        }
    }

    fn bundle(mode: EnforcementMode) -> PolicyBundle {
        PolicyBundle {
            version: 7,
            mode,
            rules: vec![PolicyRule {
                id: "deny-test-executable".into(),
                category: "test".into(),
                action: DecisionAction::Deny,
                executable_paths: vec!["/tmp/test-malware".into()],
                destination_hosts: vec![],
            }],
        }
    }

    #[test]
    fn policy_validation_rejects_duplicate_rule_ids() {
        let mut policy = bundle(EnforcementMode::Audit);
        policy.rules.push(policy.rules[0].clone());
        assert_eq!(
            validate_policy(&policy),
            Err(PolicyVerificationError::InvalidPolicy)
        );
    }

    #[test]
    fn policy_validation_rejects_empty_selector_rule() {
        let policy = PolicyBundle {
            version: 1,
            mode: EnforcementMode::Audit,
            rules: vec![PolicyRule {
                id: "empty".into(),
                category: "test".into(),
                action: DecisionAction::Alert,
                executable_paths: vec![],
                destination_hosts: vec![],
            }],
        };
        assert_eq!(
            validate_policy(&policy),
            Err(PolicyVerificationError::InvalidPolicy)
        );
    }

    #[test]
    fn signed_policy_round_trip() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let payload = serde_json::to_vec(&bundle(EnforcementMode::Enforce)).unwrap();
        let signature = signing_key.sign(&payload);
        let envelope = SignedPolicyEnvelope {
            algorithm: "Ed25519".into(),
            key_id: "test-key".into(),
            payload_b64: BASE64.encode(&payload),
            signature_b64: BASE64.encode(signature.to_bytes()),
        };

        let verified = verify_signed_policy(
            &envelope,
            signing_key.verifying_key().as_bytes(),
        )
        .unwrap();

        assert_eq!(verified.version, 7);
        assert_eq!(verified.mode, EnforcementMode::Enforce);
    }

    #[test]
    fn tampered_signed_policy_is_rejected() {
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let payload = serde_json::to_vec(&bundle(EnforcementMode::Audit)).unwrap();
        let signature = signing_key.sign(&payload);
        let mut envelope = SignedPolicyEnvelope {
            algorithm: "Ed25519".into(),
            key_id: "test-key".into(),
            payload_b64: BASE64.encode(&payload),
            signature_b64: BASE64.encode(signature.to_bytes()),
        };

        let mut tampered = payload.clone();
        tampered.push(b' ');
        envelope.payload_b64 = BASE64.encode(tampered);

        assert_eq!(
            verify_signed_policy(&envelope, signing_key.verifying_key().as_bytes()),
            Err(PolicyVerificationError::InvalidSignature)
        );
    }

    #[test]
    fn enforce_mode_denies_matching_rule() {
        let decision = bundle(EnforcementMode::Enforce).evaluate(&event());
        assert_eq!(decision.action, DecisionAction::Deny);
        assert!(decision.would_deny);
        assert_eq!(decision.rule_id.as_deref(), Some("deny-test-executable"));
    }

    #[test]
    fn audit_mode_never_enforces_deny() {
        let decision = bundle(EnforcementMode::Audit).evaluate(&event());
        assert_eq!(decision.action, DecisionAction::Alert);
        assert!(decision.would_deny);
    }

    #[test]
    fn unmatched_event_is_allowed() {
        let mut event = event();
        event.executable_path = Some("/usr/bin/true".into());
        let decision = bundle(EnforcementMode::Enforce).evaluate(&event);
        assert_eq!(decision.action, DecisionAction::Allow);
        assert!(!decision.would_deny);
    }

    #[test]
    fn multi_dimension_rule_requires_all_selectors() {
        let policy = PolicyBundle {
            version: 1,
            mode: EnforcementMode::Enforce,
            rules: vec![PolicyRule {
                id: "app-and-host".into(),
                category: "network".into(),
                action: DecisionAction::Deny,
                executable_paths: vec!["/opt/test-client".into()],
                destination_hosts: vec!["blocked.example".into()],
            }],
        };

        let mut event = event();
        event.executable_path = Some("/opt/test-client".into());
        event.destination_host = Some("allowed.example".into());
        assert_eq!(policy.evaluate(&event).action, DecisionAction::Allow);

        event.destination_host = Some("blocked.example".into());
        assert_eq!(policy.evaluate(&event).action, DecisionAction::Deny);

        event.executable_path = Some("/opt/other-client".into());
        assert_eq!(policy.evaluate(&event).action, DecisionAction::Allow);
    }

    #[test]
    fn empty_selector_rule_is_inert() {
        let policy = PolicyBundle {
            version: 1,
            mode: EnforcementMode::Enforce,
            rules: vec![PolicyRule {
                id: "empty".into(),
                category: "invalid-test".into(),
                action: DecisionAction::Deny,
                executable_paths: vec![],
                destination_hosts: vec![],
            }],
        };
        assert_eq!(policy.evaluate(&event()).action, DecisionAction::Allow);
    }

    #[test]
    fn hostname_matching_is_case_insensitive() {
        let policy = PolicyBundle {
            version: 1,
            mode: EnforcementMode::Enforce,
            rules: vec![PolicyRule {
                id: "deny-host".into(),
                category: "network".into(),
                action: DecisionAction::Deny,
                executable_paths: vec![],
                destination_hosts: vec!["bad.example".into()],
            }],
        };
        let mut event = event();
        event.destination_host = Some("BAD.EXAMPLE".into());
        assert_eq!(policy.evaluate(&event).action, DecisionAction::Deny);
    }

    #[test]
    fn policy_version_guard_rejects_downgrade() {
        let mut guard = PolicyVersionGuard::new(Some(20));
        assert!(!guard.accept(19));
        assert_eq!(guard.highest_accepted(), Some(20));
        assert!(guard.accept(20));
        assert!(guard.accept(21));
        assert_eq!(guard.highest_accepted(), Some(21));
    }

    #[test]
    fn health_contract_records_capability_state() {
        let health = AgentHealth::new("test", Some(9)).with_capability(
            "process_telemetry",
            CapabilityState::Active,
            "native",
        );
        assert_eq!(health.schema_version, 1);
        assert_eq!(health.policy_version, Some(9));
        assert_eq!(health.capabilities[0].state, CapabilityState::Active);
    }

    #[test]
    fn process_window_accumulates_file_activity() {
        let mut window = ProcessWindow::new(99, 1_000);
        window.observe_file_change(1_010, false);
        window.observe_file_change(1_020, true);
        let features = window.features();
        assert_eq!(features.unique_paths_modified, 2);
        assert_eq!(features.rename_count, 1);
        assert_eq!(window.last_event_ms, 1_020);
    }

    #[test]
    fn bounded_queue_never_exceeds_capacity() {
        let mut queue = BoundedEventQueue::new(2);
        assert!(queue.try_push(1));
        assert!(queue.try_push(2));
        assert!(!queue.try_push(3));
        assert_eq!(queue.len(), 2);
        assert_eq!(queue.dropped(), 1);
        assert_eq!(queue.pop(), Some(1));
    }

    #[test]
    fn path_tracker_deduplicates_repeated_writes() {
        let mut tracker = RansomwareTracker::new(DetectionConfig {
            window_ms: 10_000,
            max_processes: 10,
        });

        tracker.observe_path(7, 1, "/tmp/a", false);
        tracker.observe_path(7, 2, "/tmp/a", false);
        let assessment = tracker.observe_path(7, 3, "/tmp/b", true);

        assert_eq!(tracker.windows.get(&7).unwrap().unique_paths_modified, 2);
        assert_eq!(tracker.windows.get(&7).unwrap().rename_count, 1);
        assert_eq!(assessment.severity, "low");
    }

    #[test]
    fn tracker_resets_after_window() {
        let mut tracker = RansomwareTracker::new(DetectionConfig {
            window_ms: 100,
            max_processes: 10,
        });
        for now in 0..100 {
            tracker.observe(7, now, true);
        }
        assert!(tracker.observe(7, 500, false).score < 60);
    }

    #[test]
    fn tracker_bounds_process_cardinality() {
        let mut tracker = RansomwareTracker::new(DetectionConfig {
            window_ms: 10_000,
            max_processes: 2,
        });
        tracker.observe(1, 1, false);
        tracker.observe(2, 2, false);
        tracker.observe(3, 3, false);
        assert_eq!(tracker.tracked_processes(), 2);
    }

    #[test]
    fn ransomware_heuristic_combines_signals() {
        let assessment = assess_ransomware(&RansomwareFeatures {
            unique_paths_modified: 100,
            rename_count: 50,
            suspicious_process_context: true,
        });
        assert_eq!(assessment.score, 100);
        assert_eq!(assessment.severity, "critical");
        assert_eq!(assessment.reasons.len(), 3);
    }
}
