use crate::{
    http::{ControlPlaneTransport, PolicyFetch},
    policy_store::PolicyStore,
    spool::{DiskSpool, SpoolError, SpoolStats},
};
use nexus_agent_core::AgentHealth;
use serde::Serialize;

const DEFAULT_MAX_SEGMENTS_PER_CYCLE: usize = 8;

#[derive(Debug, Clone)]
pub struct RuntimeCycleReport {
    pub policy_updated: bool,
    pub health_uploaded: bool,
    pub segments_uploaded: usize,
    pub spool: Option<SpoolStats>,
    pub errors: Vec<String>,
}

pub struct RuntimeWorker<T> {
    transport: T,
    policy_store: PolicyStore,
    spool: DiskSpool,
    policy_etag: Option<String>,
    max_segments_per_cycle: usize,
}

impl<T: ControlPlaneTransport> RuntimeWorker<T> {
    pub fn new(
        transport: T,
        policy_store: PolicyStore,
        spool: DiskSpool,
    ) -> Self {
        Self {
            transport,
            policy_store,
            spool,
            policy_etag: None,
            max_segments_per_cycle: DEFAULT_MAX_SEGMENTS_PER_CYCLE,
        }
    }

    pub fn enqueue<TEvent: Serialize>(
        &mut self,
        event: &TEvent,
    ) -> Result<(), SpoolError> {
        self.spool.append(event)
    }

    pub fn run_once(&mut self, health: &AgentHealth) -> RuntimeCycleReport {
        let mut report = RuntimeCycleReport {
            policy_updated: false,
            health_uploaded: false,
            segments_uploaded: 0,
            spool: None,
            errors: Vec::new(),
        };

        match self.transport.fetch_policy(self.policy_etag.as_deref()) {
            Ok(PolicyFetch::NotModified) => {}
            Ok(PolicyFetch::Updated { body, etag }) => {
                match self.policy_store.activate(&body) {
                    Ok(_) => {
                        self.policy_etag = etag;
                        report.policy_updated = true;
                    }
                    Err(error) => {
                        report.errors.push(format!(
                            "policy activation rejected: {error}"
                        ));
                    }
                }
            }
            Err(error) => {
                report.errors.push(format!("policy fetch failed: {error}"));
            }
        }

        match self.transport.post_health(health) {
            Ok(()) => report.health_uploaded = true,
            Err(error) => report
                .errors
                .push(format!("health upload failed: {error}")),
        }

        if let Err(error) = self.spool.seal_current() {
            report
                .errors
                .push(format!("telemetry spool seal failed: {error}"));
        } else {
            for _ in 0..self.max_segments_per_cycle {
                let segment = match self.spool.next_segment() {
                    Ok(Some(path)) => path,
                    Ok(None) => break,
                    Err(error) => {
                        report
                            .errors
                            .push(format!("telemetry spool read failed: {error}"));
                        break;
                    }
                };

                let batch_id = match self.spool.segment_id(&segment) {
                    Ok(batch_id) => batch_id,
                    Err(error) => {
                        report
                            .errors
                            .push(format!("telemetry segment ID failed: {error}"));
                        break;
                    }
                };

                let payload = match self.spool.read_segment(&segment) {
                    Ok(payload) => payload,
                    Err(error) => {
                        report
                            .errors
                            .push(format!("telemetry segment read failed: {error}"));
                        break;
                    }
                };

                match self.transport.post_events(&batch_id, &payload) {
                    Ok(()) => {
                        if let Err(error) = self.spool.ack_segment(&segment) {
                            report.errors.push(format!(
                                "telemetry acknowledgement failed: {error}"
                            ));
                            break;
                        }
                        report.segments_uploaded += 1;
                    }
                    Err(error) => {
                        report
                            .errors
                            .push(format!("telemetry upload failed: {error}"));
                        break;
                    }
                }
            }
        }

        report.spool = self.spool.stats().ok();
        report
    }

    pub fn policy_etag(&self) -> Option<&str> {
        self.policy_etag.as_deref()
    }

    pub fn spool(&self) -> &DiskSpool {
        &self.spool
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::TransportError;
    use nexus_agent_core::AgentHealth;
    use std::sync::Mutex;
    use tempfile::tempdir;

    struct FakeTransport {
        uploads_fail: bool,
        uploaded: Mutex<Vec<(String, Vec<u8>)>>,
    }

    impl ControlPlaneTransport for FakeTransport {
        fn fetch_policy(
            &self,
            _previous_etag: Option<&str>,
        ) -> Result<PolicyFetch, TransportError> {
            Ok(PolicyFetch::NotModified)
        }

        fn post_health(
            &self,
            _health: &AgentHealth,
        ) -> Result<(), TransportError> {
            Ok(())
        }

        fn post_events(
            &self,
            batch_id: &str,
            jsonl: &[u8],
        ) -> Result<(), TransportError> {
            if self.uploads_fail {
                return Err(TransportError::Credential);
            }
            self.uploaded
                .lock()
                .unwrap()
                .push((batch_id.to_string(), jsonl.to_vec()));
            Ok(())
        }
    }

    fn worker(
        uploads_fail: bool,
    ) -> (tempfile::TempDir, RuntimeWorker<FakeTransport>) {
        let dir = tempdir().unwrap();
        let policy_store = PolicyStore::new(
            dir.path().join("policy.signed.json"),
            dir.path().join("policy.version"),
            [0u8; 32],
        );
        let spool = DiskSpool::open(
            dir.path().join("spool"),
            4096,
            512,
        )
        .unwrap();

        let worker = RuntimeWorker::new(
            FakeTransport {
                uploads_fail,
                uploaded: Mutex::new(Vec::new()),
            },
            policy_store,
            spool,
        );

        (dir, worker)
    }

    #[test]
    fn successful_upload_acknowledges_segment() {
        let (_dir, mut worker) = worker(false);
        worker.enqueue(&serde_json::json!({"event":"one"})).unwrap();

        let report = worker.run_once(&AgentHealth::new("test", None));
        assert_eq!(report.segments_uploaded, 1);
        assert_eq!(report.spool.unwrap().segments, 0);
        assert!(report.errors.is_empty());
    }

    #[test]
    fn retry_uses_same_stable_batch_id() {
        let (_dir, mut worker) = worker(false);
        worker.enqueue(&serde_json::json!({"event":"one"})).unwrap();

        let report = worker.run_once(&AgentHealth::new("test", None));
        assert_eq!(report.segments_uploaded, 1);

        let uploads = worker.transport.uploaded.lock().unwrap();
        assert_eq!(uploads.len(), 1);
        assert!(!uploads[0].0.is_empty());
        assert!(uploads[0].0.bytes().all(|byte| byte.is_ascii_digit()));
    }

    #[test]
    fn failed_upload_keeps_segment_for_retry() {
        let (_dir, mut worker) = worker(true);
        worker.enqueue(&serde_json::json!({"event":"one"})).unwrap();

        let report = worker.run_once(&AgentHealth::new("test", None));
        assert_eq!(report.segments_uploaded, 0);
        assert_eq!(report.spool.unwrap().segments, 1);
        assert!(!report.errors.is_empty());
    }
}
