use nexus_agent_core::{DecisionAction, EnforcementMode, PolicyBundle};
use std::{
    collections::HashSet,
    io::Write,
    net::Ipv4Addr,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

const TABLE_FAMILY: &str = "inet";
const TABLE_NAME: &str = "votal_nexus_runtime";
const SET_NAME: &str = "blocked_ipv4";
const LEASE_SECONDS: u64 = 120;
const REFRESH_SECONDS: u64 = 60;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkPlan {
    pub rule_id: String,
    pub remote_ipv4: Ipv4Addr,
}

pub fn select_network_plan(
    policy: &PolicyBundle,
) -> Result<Vec<NetworkPlan>, String> {
    if policy.mode != EnforcementMode::Enforce {
        return Ok(Vec::new());
    }

    let mut plans = Vec::new();
    let mut seen = HashSet::new();

    for rule in policy.rules.iter().filter(|rule| {
        rule.action == DecisionAction::Deny && !rule.destination_hosts.is_empty()
    }) {
        if !rule.executable_paths.is_empty() {
            return Err(format!(
                "Linux nftables cannot faithfully enforce executable-scoped network rule {}",
                rule.id
            ));
        }

        for destination in &rule.destination_hosts {
            let remote_ipv4 = destination.parse::<Ipv4Addr>().map_err(|_| {
                format!(
                    "Linux nftables requires exact IPv4 destinations; rule {} contains {}",
                    rule.id, destination
                )
            })?;

            if seen.insert(remote_ipv4) {
                plans.push(NetworkPlan {
                    rule_id: rule.id.clone(),
                    remote_ipv4,
                });
            }
        }
    }

    if plans.len() > 256 {
        return Err("expanded Linux network policy exceeds 256 exact IPv4 destinations".to_string());
    }

    Ok(plans)
}

pub struct NftLease {
    plans: Vec<NetworkPlan>,
    last_refresh: Instant,
}

impl NftLease {
    pub fn start(plans: Vec<NetworkPlan>) -> Result<Self, String> {
        if plans.is_empty() {
            return Err("cannot start nftables lease without destinations".to_string());
        }
        ensure_nft_available()?;
        remove_runtime_table();

        let setup = format!(
            "table {TABLE_FAMILY} {TABLE_NAME} {{\n             set {SET_NAME} {{ type ipv4_addr; flags timeout; timeout {LEASE_SECONDS}s; }}\n             chain output {{ type filter hook output priority -5; policy accept; \
             ip daddr @{SET_NAME} counter drop comment \"nexus-runtime\"; }}\n             }}\n"
        );

        run_nft_batch(&setup)?;

        let mut lease = Self {
            plans,
            last_refresh: Instant::now() - Duration::from_secs(REFRESH_SECONDS),
        };

        if let Err(error) = lease.refresh() {
            remove_runtime_table();
            return Err(error);
        }

        Ok(lease)
    }

    pub fn refresh_if_due(&mut self) -> Result<(), String> {
        if self.last_refresh.elapsed() >= Duration::from_secs(REFRESH_SECONDS) {
            self.refresh()?;
        }
        Ok(())
    }

    pub fn detail(&self) -> String {
        format!(
            "expiring nftables enforcement active destinations={} lease={}s refresh={}s",
            self.plans.len(),
            LEASE_SECONDS,
            REFRESH_SECONDS,
        )
    }

    fn refresh(&mut self) -> Result<(), String> {
        let elements = self
            .plans
            .iter()
            .map(|plan| format!("{} timeout {LEASE_SECONDS}s", plan.remote_ipv4))
            .collect::<Vec<_>>()
            .join(", ");
        let batch = format!(
            "flush set {TABLE_FAMILY} {TABLE_NAME} {SET_NAME}\n             add element {TABLE_FAMILY} {TABLE_NAME} {SET_NAME} \
             {{ {elements} }}\n"
        );
        run_nft_batch(&batch)?;
        self.last_refresh = Instant::now();
        Ok(())
    }
}

impl Drop for NftLease {
    fn drop(&mut self) {
        remove_runtime_table();
    }
}

fn ensure_nft_available() -> Result<(), String> {
    let status = Command::new("nft")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| format!("cannot execute nft: {error}"))?;

    if status.success() {
        Ok(())
    } else {
        Err(format!("nft --version exited with {status}"))
    }
}

fn run_nft_batch(batch: &str) -> Result<(), String> {
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("cannot start nft: {error}"))?;

    if let Some(stdin) = child.stdin.as_mut() {
        stdin
            .write_all(batch.as_bytes())
            .map_err(|error| format!("cannot write nft batch: {error}"))?;
    }

    let output = child
        .wait_with_output()
        .map_err(|error| format!("cannot wait for nft: {error}"))?;

    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "nft batch failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn remove_runtime_table() {
    let _ = Command::new("nft")
        .args(["delete", "table", TABLE_FAMILY, TABLE_NAME])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_agent_core::PolicyRule;

    fn policy(
        mode: EnforcementMode,
        destinations: Vec<&str>,
        executables: Vec<&str>,
    ) -> PolicyBundle {
        PolicyBundle {
            version: 1,
            mode,
            rules: vec![PolicyRule {
                id: "network-test".into(),
                category: "network".into(),
                action: DecisionAction::Deny,
                executable_paths: executables.into_iter().map(str::to_string).collect(),
                destination_hosts: destinations.into_iter().map(str::to_string).collect(),
            }],
            ransomware_response: None,
        }
    }

    #[test]
    fn audit_policy_has_no_enforcement_plan() {
        assert_eq!(
            select_network_plan(&policy(
                EnforcementMode::Audit,
                vec!["203.0.113.10"],
                vec![],
            ))
            .unwrap(),
            None
        );
    }

    #[test]
    fn exact_ipv4_builds_plan() {
        let plans = select_network_plan(&policy(
            EnforcementMode::Enforce,
            vec!["203.0.113.10"],
            vec![],
        ))
        .unwrap();

        assert_eq!(plans.len(), 1);
        assert_eq!(
            plans[0].remote_ipv4,
            "203.0.113.10".parse::<Ipv4Addr>().unwrap()
        );
    }

    #[test]
    fn multiple_exact_ipv4_destinations_build_multiple_plans() {
        let plans = select_network_plan(&policy(
            EnforcementMode::Enforce,
            vec!["203.0.113.10", "203.0.113.11"],
            vec![],
        ))
        .unwrap();

        assert_eq!(plans.len(), 2);
        assert!(plans.iter().any(|plan|
            plan.remote_ipv4 == "203.0.113.10".parse::<Ipv4Addr>().unwrap()
        ));
        assert!(plans.iter().any(|plan|
            plan.remote_ipv4 == "203.0.113.11".parse::<Ipv4Addr>().unwrap()
        ));
    }

    #[test]
    fn executable_scoped_rule_is_not_partially_enforced() {
        assert!(select_network_plan(&policy(
            EnforcementMode::Enforce,
            vec!["203.0.113.10"],
            vec!["/usr/bin/curl"],
        ))
        .is_err());
    }

    #[test]
    fn hostname_rule_stays_unsupported() {
        assert!(select_network_plan(&policy(
            EnforcementMode::Enforce,
            vec!["example.com"],
            vec![],
        ))
        .is_err());
    }
}
