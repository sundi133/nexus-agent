use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};
use thiserror::Error;

const MAX_CREDENTIAL_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceCredential {
    pub device_id: String,
    pub bearer_token: String,
    #[serde(default)]
    pub expires_at: Option<String>,
}

#[derive(Debug, Error)]
pub enum DeviceCredentialError {
    #[error("credential I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("credential file must be a regular non-symlink file")]
    UnsafeFile,
    #[error("credential file permissions are too broad")]
    InsecurePermissions,
    #[error("credential JSON is invalid")]
    InvalidJson,
    #[error("credential fields are invalid")]
    InvalidFields,
    #[error("credential file is too large")]
    TooLarge,
}

impl DeviceCredential {
    pub fn validate(&self) -> Result<(), DeviceCredentialError> {
        if self.device_id.is_empty()
            || self.device_id.len() > 256
            || !self
                .device_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
            || self.bearer_token.len() < 16
            || self.bearer_token.len() > 16 * 1024
            || self
                .bearer_token
                .chars()
                .any(|ch| ch == '\r' || ch == '\n')
            || self
                .expires_at
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.len() > 128)
        {
            return Err(DeviceCredentialError::InvalidFields);
        }
        Ok(())
    }
}

pub fn load_device_credential(path: &Path) -> Result<DeviceCredential, DeviceCredentialError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(DeviceCredentialError::UnsafeFile);
    }
    if metadata.len() > MAX_CREDENTIAL_BYTES {
        return Err(DeviceCredentialError::TooLarge);
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o007 != 0 {
            return Err(DeviceCredentialError::InsecurePermissions);
        }
    }

    let bytes = fs::read(path)?;
    let credential: DeviceCredential =
        serde_json::from_slice(&bytes).map_err(|_| DeviceCredentialError::InvalidJson)?;
    credential.validate()?;
    Ok(credential)
}

pub fn atomic_write_device_credential(
    path: &Path,
    credential: &DeviceCredential,
) -> Result<(), DeviceCredentialError> {
    credential.validate()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let filename = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("device.credential.json");
    let tmp: PathBuf = path.with_file_name(format!(".{filename}.tmp"));

    let payload =
        serde_json::to_vec_pretty(credential).map_err(|_| DeviceCredentialError::InvalidJson)?;

    {
        let mut file = fs::File::create(&tmp)?;
        file.write_all(&payload)?;
        file.write_all(b"\n")?;
        file.sync_all()?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
        }
    }

    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn credential() -> DeviceCredential {
        DeviceCredential {
            device_id: "device-123".into(),
            bearer_token: "abcdefghijklmnopqrstuvwxyz012345".into(),
            expires_at: Some("2026-11-01T00:00:00Z".into()),
        }
    }

    #[test]
    fn round_trip_protected_credential() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("device.json");
        atomic_write_device_credential(&path, &credential()).unwrap();
        assert_eq!(load_device_credential(&path).unwrap(), credential());
    }

    #[test]
    fn rejects_unsafe_device_id() {
        let mut value = credential();
        value.device_id = "bad device\nheader".into();
        assert!(matches!(
            value.validate(),
            Err(DeviceCredentialError::InvalidFields)
        ));
    }

    #[test]
    fn rejects_short_token() {
        let mut value = credential();
        value.bearer_token = "short".into();
        assert!(matches!(
            value.validate(),
            Err(DeviceCredentialError::InvalidFields)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_world_readable_credential() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("device.json");
        atomic_write_device_credential(&path, &credential()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            load_device_credential(&path),
            Err(DeviceCredentialError::InsecurePermissions)
        ));
    }
}
