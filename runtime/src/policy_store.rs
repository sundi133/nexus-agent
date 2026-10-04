use nexus_agent_core::{
    verify_signed_policy, PolicyBundle, PolicyVerificationError, SignedPolicyEnvelope,
};
use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};
use thiserror::Error;

const MAX_SIGNED_POLICY_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone)]
pub struct ActivatedPolicy {
    pub policy: PolicyBundle,
    pub signed_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct PolicyStore {
    signed_path: PathBuf,
    watermark_path: PathBuf,
    public_key: [u8; 32],
}

#[derive(Debug, Error)]
pub enum PolicyStoreError {
    #[error("policy envelope exceeds maximum size")]
    TooLarge,
    #[error("invalid policy envelope JSON")]
    InvalidEnvelope,
    #[error("policy verification failed: {0:?}")]
    Verification(PolicyVerificationError),
    #[error("policy downgrade rejected: current={current}, candidate={candidate}")]
    Downgrade { current: u64, candidate: u64 },
    #[error("policy version conflict: version={version} already exists with different signed content")]
    VersionConflict { version: u64 },
    #[error("policy state I/O failed: {0}")]
    Io(#[from] io::Error),
}

impl PolicyStore {
    pub fn new(
        signed_path: PathBuf,
        watermark_path: PathBuf,
        public_key: [u8; 32],
    ) -> Self {
        Self {
            signed_path,
            watermark_path,
            public_key,
        }
    }

    pub fn activate(
        &self,
        envelope_bytes: &[u8],
    ) -> Result<ActivatedPolicy, PolicyStoreError> {
        if envelope_bytes.len() > MAX_SIGNED_POLICY_BYTES {
            return Err(PolicyStoreError::TooLarge);
        }

        let envelope: SignedPolicyEnvelope =
            serde_json::from_slice(envelope_bytes)
                .map_err(|_| PolicyStoreError::InvalidEnvelope)?;

        let policy = verify_signed_policy(&envelope, &self.public_key)
            .map_err(PolicyStoreError::Verification)?;

        let current = self.watermark()?;
        if current.is_some_and(|version| policy.version < version) {
            return Err(PolicyStoreError::Downgrade {
                current: current.unwrap_or_default(),
                candidate: policy.version,
            });
        }

        if current == Some(policy.version) {
            match fs::read(&self.signed_path) {
                Ok(existing) if existing == envelope_bytes => {
                    return Ok(ActivatedPolicy {
                        policy,
                        signed_path: self.signed_path.clone(),
                    });
                }
                Ok(_) => {
                    return Err(PolicyStoreError::VersionConflict {
                        version: policy.version,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }

        atomic_write(&self.signed_path, envelope_bytes)?;
        atomic_write(
            &self.watermark_path,
            format!("{}\n", policy.version).as_bytes(),
        )?;

        Ok(ActivatedPolicy {
            policy,
            signed_path: self.signed_path.clone(),
        })
    }

    pub fn load_active(&self) -> Result<Option<ActivatedPolicy>, PolicyStoreError> {
        let bytes = match fs::read(&self.signed_path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };

        if bytes.len() > MAX_SIGNED_POLICY_BYTES {
            return Err(PolicyStoreError::TooLarge);
        }

        let envelope: SignedPolicyEnvelope =
            serde_json::from_slice(&bytes)
                .map_err(|_| PolicyStoreError::InvalidEnvelope)?;
        let policy = verify_signed_policy(&envelope, &self.public_key)
            .map_err(PolicyStoreError::Verification)?;

        let current = self.watermark()?;
        if current.is_some_and(|version| policy.version < version) {
            return Err(PolicyStoreError::Downgrade {
                current: current.unwrap_or_default(),
                candidate: policy.version,
            });
        }

        Ok(Some(ActivatedPolicy {
            policy,
            signed_path: self.signed_path.clone(),
        }))
    }

    pub fn watermark(&self) -> Result<Option<u64>, io::Error> {
        match fs::read_to_string(&self.watermark_path) {
            Ok(value) => Ok(value.trim().parse::<u64>().ok()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }
}

fn atomic_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("state");
    let tmp = path.with_file_name(format!(".{file_name}.tmp"));

    {
        let mut file = fs::File::create(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }

    fs::rename(tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
    use ed25519_dalek::{Signer, SigningKey};
    use nexus_agent_core::{DecisionAction, EnforcementMode, PolicyRule};
    use tempfile::tempdir;

    fn envelope(signing_key: &SigningKey, version: u64) -> Vec<u8> {
        let policy = PolicyBundle {
            version,
            mode: EnforcementMode::Audit,
            rules: vec![PolicyRule {
                id: "test".into(),
                category: "test".into(),
                action: DecisionAction::Alert,
                executable_paths: vec!["/tmp/test".into()],
                destination_hosts: vec![],
            }],
            agent_action_rules: vec![],
            ransomware_response: None,
        };
        let payload = serde_json::to_vec(&policy).unwrap();
        let signed = SignedPolicyEnvelope {
            algorithm: "Ed25519".into(),
            key_id: "test-key".into(),
            payload_b64: BASE64.encode(&payload),
            signature_b64: BASE64.encode(signing_key.sign(&payload).to_bytes()),
        };
        serde_json::to_vec(&signed).unwrap()
    }

    #[test]
    fn identical_same_version_activation_is_idempotent() {
        let dir = tempdir().unwrap();
        let signing_key = SigningKey::from_bytes(&[12u8; 32]);
        let store = PolicyStore::new(
            dir.path().join("policy.signed.json"),
            dir.path().join("policy.version"),
            *signing_key.verifying_key().as_bytes(),
        );

        let signed = envelope(&signing_key, 10);
        store.activate(&signed).unwrap();
        let active = store.activate(&signed).unwrap();
        assert_eq!(active.policy.version, 10);
    }

    #[test]
    fn different_content_cannot_reuse_same_version() {
        let dir = tempdir().unwrap();
        let signing_key = SigningKey::from_bytes(&[13u8; 32]);
        let store = PolicyStore::new(
            dir.path().join("policy.signed.json"),
            dir.path().join("policy.version"),
            *signing_key.verifying_key().as_bytes(),
        );

        let first = envelope(&signing_key, 10);
        store.activate(&first).unwrap();

        let policy = PolicyBundle {
            version: 10,
            mode: EnforcementMode::Enforce,
            rules: vec![PolicyRule {
                id: "changed".into(),
                category: "test".into(),
                action: DecisionAction::Deny,
                executable_paths: vec!["/tmp/changed".into()],
                destination_hosts: vec![],
            }],
            agent_action_rules: vec![],
            ransomware_response: None,
        };
        let payload = serde_json::to_vec(&policy).unwrap();
        let changed = SignedPolicyEnvelope {
            algorithm: "Ed25519".into(),
            key_id: "test-key".into(),
            payload_b64: BASE64.encode(&payload),
            signature_b64: BASE64.encode(signing_key.sign(&payload).to_bytes()),
        };
        let changed_bytes = serde_json::to_vec(&changed).unwrap();

        let err = store.activate(&changed_bytes).unwrap_err();
        assert!(matches!(err, PolicyStoreError::VersionConflict { version: 10 }));
    }

    #[test]
    fn persists_verified_policy_and_rejects_downgrade() {
        let dir = tempdir().unwrap();
        let signing_key = SigningKey::from_bytes(&[11u8; 32]);
        let store = PolicyStore::new(
            dir.path().join("policy.signed.json"),
            dir.path().join("policy.version"),
            *signing_key.verifying_key().as_bytes(),
        );

        store.activate(&envelope(&signing_key, 10)).unwrap();
        let err = store.activate(&envelope(&signing_key, 9)).unwrap_err();
        assert!(matches!(err, PolicyStoreError::Downgrade { .. }));

        let active = store.load_active().unwrap().unwrap();
        assert_eq!(active.policy.version, 10);
    }
}
