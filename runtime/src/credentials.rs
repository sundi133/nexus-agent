use std::{fs, io, path::Path};

#[derive(Debug)]
pub enum SecretFileError {
    Io(io::Error),
    NotRegularFile,
    Symlink,
    InsecurePermissions,
    InvalidLength,
    ContainsNewline,
}

pub fn read_secret_file(
    path: &Path,
    min_len: usize,
    max_len: usize,
    reject_newlines: bool,
) -> Result<String, SecretFileError> {
    let metadata = fs::symlink_metadata(path).map_err(SecretFileError::Io)?;
    if metadata.file_type().is_symlink() {
        return Err(SecretFileError::Symlink);
    }
    if !metadata.is_file() {
        return Err(SecretFileError::NotRegularFile);
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Group read is allowed for root-owned deployment files shared with a
        // dedicated service/producer group. No permissions may be granted to
        // "other".
        if metadata.permissions().mode() & 0o007 != 0 {
            return Err(SecretFileError::InsecurePermissions);
        }
    }

    let value = fs::read_to_string(path).map_err(SecretFileError::Io)?;
    let value = value.trim().to_string();

    if value.len() < min_len || value.len() > max_len {
        return Err(SecretFileError::InvalidLength);
    }
    if reject_newlines && value.chars().any(|ch| ch == '\r' || ch == '\n') {
        return Err(SecretFileError::ContainsNewline);
    }

    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn reads_regular_secret() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("token");
        fs::write(&path, "abcdefghijklmnopqrstuvwxyz012345\n").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        }

        let value = read_secret_file(&path, 32, 512, true).unwrap();
        assert_eq!(value, "abcdefghijklmnopqrstuvwxyz012345");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_world_accessible_secret() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let path = dir.path().join("token");
        fs::write(&path, "abcdefghijklmnopqrstuvwxyz012345").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        assert!(matches!(
            read_secret_file(&path, 32, 512, true),
            Err(SecretFileError::InsecurePermissions)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_secret() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let real = dir.path().join("real");
        let link = dir.path().join("link");
        fs::write(&real, "abcdefghijklmnopqrstuvwxyz012345").unwrap();
        symlink(&real, &link).unwrap();

        assert!(matches!(
            read_secret_file(&link, 32, 512, true),
            Err(SecretFileError::Symlink)
        ));
    }
}
