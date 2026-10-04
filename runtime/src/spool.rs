use serde::Serialize;
use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpoolStats {
    pub bytes: u64,
    pub segments: usize,
    pub dropped_segments: u64,
}

#[derive(Debug)]
pub struct DiskSpool {
    dir: PathBuf,
    max_bytes: u64,
    segment_max_bytes: u64,
    sequence: u64,
    dropped_segments: u64,
}

#[derive(Debug, Error)]
pub enum SpoolError {
    #[error("spool I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("single record exceeds segment limit")]
    RecordTooLarge,
}

impl DiskSpool {
    pub fn open(
        dir: PathBuf,
        max_bytes: u64,
        segment_max_bytes: u64,
    ) -> Result<Self, SpoolError> {
        fs::create_dir_all(&dir)?;
        let sequence = current_millis();
        let mut spool = Self {
            dir,
            max_bytes,
            segment_max_bytes,
            sequence,
            dropped_segments: 0,
        };
        spool.enforce_limit()?;
        Ok(spool)
    }

    pub fn append<T: Serialize>(&mut self, record: &T) -> Result<(), SpoolError> {
        let mut line = serde_json::to_vec(record)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        line.push(b'\n');

        if line.len() as u64 > self.segment_max_bytes {
            return Err(SpoolError::RecordTooLarge);
        }

        let current = self.current_segment_path();
        let current_len = fs::metadata(&current).map(|m| m.len()).unwrap_or(0);

        if current_len > 0
            && current_len.saturating_add(line.len() as u64) > self.segment_max_bytes
        {
            self.sequence = self.sequence.saturating_add(1);
        }

        let path = self.current_segment_path();
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        file.write_all(&line)?;
        file.sync_data()?;

        self.enforce_limit()
    }

    pub fn seal_current(&mut self) -> Result<(), SpoolError> {
        let current = self.current_segment_path();
        if fs::metadata(&current).map(|m| m.len()).unwrap_or(0) > 0 {
            self.sequence = self.sequence.saturating_add(1);
        }
        Ok(())
    }

    pub fn next_segment(&self) -> Result<Option<PathBuf>, SpoolError> {
        let mut segments = self.segments()?;
        segments.sort();
        Ok(segments.into_iter().next())
    }

    pub fn read_segment(&self, path: &Path) -> Result<Vec<u8>, SpoolError> {
        Ok(fs::read(path)?)
    }
    pub fn segment_id(&self, path: &Path) -> Result<String, SpoolError> {
        if path.parent() != Some(self.dir.as_path()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "segment is outside spool directory",
            )
            .into());
        }

        let stem = path
            .file_stem()
            .and_then(|value| value.to_str())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid segment name"))?;

        if stem.is_empty() || !stem.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "segment ID must be numeric",
            )
            .into());
        }

        Ok(stem.to_string())
    }


    pub fn ack_segment(&self, path: &Path) -> Result<(), SpoolError> {
        if path.parent() != Some(self.dir.as_path()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "segment is outside spool directory",
            )
            .into());
        }
        fs::remove_file(path)?;
        Ok(())
    }

    pub fn stats(&self) -> Result<SpoolStats, SpoolError> {
        let segments = self.segments()?;
        let bytes = segments.iter().try_fold(0u64, |sum, path| {
            Ok::<u64, io::Error>(sum.saturating_add(fs::metadata(path)?.len()))
        })?;
        Ok(SpoolStats {
            bytes,
            segments: segments.len(),
            dropped_segments: self.dropped_segments,
        })
    }

    fn enforce_limit(&mut self) -> Result<(), SpoolError> {
        loop {
            let mut segments = self.segments()?;
            segments.sort();

            let total = segments.iter().try_fold(0u64, |sum, path| {
                Ok::<u64, io::Error>(sum.saturating_add(fs::metadata(path)?.len()))
            })?;

            if total <= self.max_bytes || segments.is_empty() {
                return Ok(());
            }

            fs::remove_file(&segments[0])?;
            self.dropped_segments = self.dropped_segments.saturating_add(1);
        }
    }

    fn segments(&self) -> Result<Vec<PathBuf>, io::Error> {
        let mut result = Vec::new();
        for entry in fs::read_dir(&self.dir)? {
            let path = entry?.path();
            if path.extension().and_then(|v| v.to_str()) == Some("jsonl") {
                result.push(path);
            }
        }
        Ok(result)
    }

    fn current_segment_path(&self) -> PathBuf {
        self.dir.join(format!("{:020}.jsonl", self.sequence))
    }
}

fn current_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::tempdir;

    #[test]
    fn rotates_and_bounds_disk_usage() {
        let dir = tempdir().unwrap();
        let mut spool = DiskSpool::open(dir.path().to_path_buf(), 180, 80).unwrap();

        for i in 0..20 {
            spool.append(&json!({"event": i, "value": "abcdefghij"})).unwrap();
        }

        let stats = spool.stats().unwrap();
        assert!(stats.bytes <= 180);
        assert!(stats.dropped_segments > 0);
    }

    #[test]
    fn segment_id_is_stable_filename_stem() {
        let dir = tempdir().unwrap();
        let mut spool = DiskSpool::open(dir.path().to_path_buf(), 1024, 256).unwrap();
        spool.append(&json!({"event":"one"})).unwrap();
        spool.seal_current().unwrap();
        let path = spool.next_segment().unwrap().unwrap();
        let first = spool.segment_id(&path).unwrap();
        let second = spool.segment_id(&path).unwrap();
        assert_eq!(first, second);
        assert!(first.bytes().all(|byte| byte.is_ascii_digit()));
    }

    #[test]
    fn ack_requires_owned_segment() {
        let dir = tempdir().unwrap();
        let spool = DiskSpool::open(dir.path().to_path_buf(), 1024, 256).unwrap();
        let outside = dir.path().parent().unwrap().join("outside.jsonl");
        assert!(spool.ack_segment(&outside).is_err());
    }
}
