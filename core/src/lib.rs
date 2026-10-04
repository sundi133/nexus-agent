use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};

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
            let path_matches = !rule.executable_paths.is_empty()
                && event.executable_path.as_ref().is_some_and(|path| {
                    rule.executable_paths.iter().any(|candidate| candidate == path)
                });

            let host_matches = !rule.destination_hosts.is_empty()
                && event.destination_host.as_ref().is_some_and(|host| {
                    rule.destination_hosts.iter().any(|candidate| {
                        candidate.eq_ignore_ascii_case(host)
                    })
                });

            if !(path_matches || host_matches) {
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
}

impl RansomwareTracker {
    pub fn new(config: DetectionConfig) -> Self {
        Self {
            config,
            windows: HashMap::new(),
        }
    }

    pub fn observe(&mut self, pid: u32, now_ms: u64, renamed: bool) -> RansomwareAssessment {
        self.expire(now_ms);

        if !self.windows.contains_key(&pid) && self.windows.len() >= self.config.max_processes {
            if let Some(oldest_pid) = self.windows
                .values()
                .min_by_key(|window| window.last_event_ms)
                .map(|window| window.pid)
            {
                self.windows.remove(&oldest_pid);
            }
        }

        let window = self.windows
            .entry(pid)
            .or_insert_with(|| ProcessWindow::new(pid, now_ms));

        if now_ms.saturating_sub(window.window_started_ms) > self.config.window_ms {
            window.reset(now_ms);
        }

        window.observe_file_change(now_ms, renamed);
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
        self.windows.retain(|_, window| {
            now_ms.saturating_sub(window.last_event_ms) <= window_ms
        });
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
