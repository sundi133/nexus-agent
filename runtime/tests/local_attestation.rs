#![cfg(unix)]

use nexus_agent_core::{
    AgentActionEvent, AgentActionKind, AgentActionRule, DecisionAction, EnforcementMode,
    PolicyBundle,
};
use nexus_agent_runtime::{
    authorize_action, spawn_local_ingest_unix, AgentActionAuditRecord, LocalAuthorizationTarget,
    LocalIngestAuth, ProducerCredential,
};
use std::{
    sync::{mpsc, Arc, RwLock},
    thread,
    time::Duration,
};
use tempfile::tempdir;

#[test]
fn unix_socket_attestation_drives_agent_policy_decision() {
    let dir = tempdir().unwrap();
    let socket = dir.path().join("agent-actions.sock");
    let token = "t".repeat(32);

    let policy = PolicyBundle {
        version: 101,
        mode: EnforcementMode::Enforce,
        rules: vec![],
        agent_action_rules: vec![AgentActionRule {
            id: "deny-attested-agent-write".into(),
            action: DecisionAction::Deny,
            kinds: vec![AgentActionKind::McpToolCall],
            agent_ids: vec!["integration-agent".into()],
            mcp_servers: vec!["filesystem".into()],
            tool_names: vec!["write_file".into()],
            operations: vec!["write".into()],
            resource_prefixes: vec!["/etc/".into()],
            risk_tags: vec![],
        }],
        ransomware_response: None,
    };

    let expected_uid = unsafe { libc::geteuid() };
    let auth = LocalIngestAuth::BoundProducers(vec![ProducerCredential {
        agent_id: "integration-agent".into(),
        token: token.clone(),
        expected_uid: Some(expected_uid),
        executable_paths: vec![],
        executable_sha256: vec![],
    }]);

    let (tx, rx) = mpsc::channel::<AgentActionAuditRecord>();
    let _server = spawn_local_ingest_unix(
        socket.clone(),
        auth,
        Arc::new(RwLock::new(Some(policy))),
        tx,
    )
    .unwrap();

    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(socket.exists());

    let event = AgentActionEvent {
        event_id: "integration-1".into(),
        timestamp: "2026-10-04T00:00:00Z".into(),
        device_id: "integration-device".into(),
        pid: None,
        agent_id: Some("integration-agent".into()),
        session_id: Some("session-1".into()),
        kind: AgentActionKind::McpToolCall,
        mcp_server: Some("filesystem".into()),
        tool_name: Some("write_file".into()),
        operation: "write".into(),
        resource: Some("/etc/hosts".into()),
        risk_tags: vec![],
    };

    let decision = authorize_action(
        &LocalAuthorizationTarget::Unix(socket),
        &token,
        &event,
    )
    .unwrap();

    assert_eq!(decision.action, DecisionAction::Deny);
    assert_eq!(decision.policy_version, 101);

    let audit = rx.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(audit.event.agent_id.as_deref(), Some("integration-agent"));
    assert_eq!(audit.event.pid, Some(std::process::id()));
    assert!(audit.producer_attestation.credential_bound);
    assert!(audit.producer_attestation.kernel_peer);
    assert_eq!(audit.producer_attestation.uid, Some(expected_uid));
    assert_eq!(audit.decision.action, DecisionAction::Deny);
}
