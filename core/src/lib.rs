use serde::{Deserialize, Serialize};

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
