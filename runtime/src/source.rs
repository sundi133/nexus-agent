use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fs,
    io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

const MAX_LINE_BYTES: usize = 1024 * 1024;
const MAX_RECORDS_PER_CYCLE: usize = 4096;
const ANCHOR_BYTES: u64 = 64;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IngestStats {
    pub records: usize,
    pub invalid_records: usize,
    pub bytes_advanced: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SourceCheckpoint {
    offset: u64,
    anchor_hash: u64,
}

#[derive(Debug, Clone)]
pub struct JsonlTailer {
    source_path: PathBuf,
    offset_path: PathBuf,
}

impl JsonlTailer {
    pub fn new(source_path: PathBuf, offset_path: PathBuf) -> Self {
        Self {
            source_path,
            offset_path,
        }
    }

    pub fn ingest<F>(&self, mut on_record: F) -> io::Result<IngestStats>
    where
        F: FnMut(&Value) -> io::Result<()>,
    {
        let file = match fs::File::open(&self.source_path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(IngestStats::default())
            }
            Err(error) => return Err(error),
        };

        let source_len = file.metadata()?.len();
        let checkpoint = self.read_checkpoint()?;

        let mut offset = checkpoint.as_ref().map_or(0, |saved| saved.offset);
        if offset > source_len {
            offset = 0;
        } else if let Some(saved) = checkpoint.as_ref() {
            if saved.offset > 0
                && self.anchor_hash(saved.offset)? != saved.anchor_hash
            {
                offset = 0;
            }
        }

        let mut reader = BufReader::new(file);
        reader.seek(SeekFrom::Start(offset))?;

        let mut stats = IngestStats::default();
        let mut committed_offset = offset;

        for _ in 0..MAX_RECORDS_PER_CYCLE {
            let start = reader.stream_position()?;
            let mut line = Vec::new();
            let read = reader.read_until(b'\n', &mut line)?;
            if read == 0 {
                break;
            }

            if !line.ends_with(b"\n") {
                reader.seek(SeekFrom::Start(start))?;
                break;
            }

            let end = reader.stream_position()?;
            if line.len() > MAX_LINE_BYTES {
                stats.invalid_records = stats.invalid_records.saturating_add(1);
                committed_offset = end;
                continue;
            }

            while matches!(line.last(), Some(b'\n' | b'\r')) {
                line.pop();
            }

            if line.is_empty() {
                committed_offset = end;
                continue;
            }

            match serde_json::from_slice::<Value>(&line) {
                Ok(record) => {
                    on_record(&record)?;
                    stats.records = stats.records.saturating_add(1);
                    committed_offset = end;
                }
                Err(_) => {
                    stats.invalid_records = stats.invalid_records.saturating_add(1);
                    committed_offset = end;
                }
            }
        }

        if committed_offset != offset {
            self.write_checkpoint(committed_offset)?;
            stats.bytes_advanced = committed_offset.saturating_sub(offset);
        }

        Ok(stats)
    }

    fn read_checkpoint(&self) -> io::Result<Option<SourceCheckpoint>> {
        let raw = match fs::read_to_string(&self.offset_path) {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };

        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }

        if let Ok(checkpoint) = serde_json::from_str::<SourceCheckpoint>(trimmed) {
            return Ok(Some(checkpoint));
        }

        // Backward compatibility with the initial plain numeric checkpoint.
        if let Ok(offset) = trimmed.parse::<u64>() {
            return Ok(Some(SourceCheckpoint {
                offset,
                anchor_hash: self.anchor_hash(offset).unwrap_or_default(),
            }));
        }

        Ok(None)
    }

    fn write_checkpoint(&self, offset: u64) -> io::Result<()> {
        if let Some(parent) = self.offset_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let checkpoint = SourceCheckpoint {
            offset,
            anchor_hash: self.anchor_hash(offset)?,
        };
        let encoded = serde_json::to_vec(&checkpoint)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;

        let file_name = self
            .offset_path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("events.offset");
        let tmp = self.offset_path.with_file_name(format!(".{file_name}.tmp"));

        {
            let mut file = fs::File::create(&tmp)?;
            file.write_all(&encoded)?;
            file.write_all(b"\n")?;
            file.sync_all()?;
        }

        fs::rename(tmp, &self.offset_path)
    }

    fn anchor_hash(&self, offset: u64) -> io::Result<u64> {
        hash_anchor(&self.source_path, offset)
    }
}

fn hash_anchor(path: &Path, offset: u64) -> io::Result<u64> {
    let mut file = fs::File::open(path)?;
    let len = file.metadata()?.len();
    let bounded_offset = offset.min(len);
    let start = bounded_offset.saturating_sub(ANCHOR_BYTES);
    let size = bounded_offset.saturating_sub(start) as usize;

    file.seek(SeekFrom::Start(start))?;
    let mut bytes = vec![0u8; size];
    if size > 0 {
        file.read_exact(&mut bytes)?;
    }

    // FNV-1a 64-bit is sufficient here as a rotation/replacement anchor.
    // This is not a cryptographic integrity mechanism; signed policy uses Ed25519.
    let mut hash = 0xcbf29ce484222325u64;
    for byte in bytes {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    Ok(hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn resumes_from_persisted_offset() {
        let dir = tempdir().unwrap();
        let source = dir.path().join("events.jsonl");
        let offset = dir.path().join("events.offset");
        fs::write(&source, b"{\"id\":1}\n{\"id\":2}\n").unwrap();

        let tailer = JsonlTailer::new(source.clone(), offset);
        let mut first = Vec::new();
        let stats = tailer
            .ingest(|value| {
                first.push(value["id"].as_i64().unwrap());
                Ok(())
            })
            .unwrap();

        assert_eq!(stats.records, 2);
        assert_eq!(first, vec![1, 2]);

        let mut second = Vec::new();
        let stats = tailer
            .ingest(|value| {
                second.push(value["id"].as_i64().unwrap());
                Ok(())
            })
            .unwrap();

        assert_eq!(stats.records, 0);
        assert!(second.is_empty());
    }

    #[test]
    fn partial_trailing_line_is_not_consumed() {
        let dir = tempdir().unwrap();
        let source = dir.path().join("events.jsonl");
        let offset = dir.path().join("events.offset");
        fs::write(&source, b"{\"id\":1}\n{\"id\":2}").unwrap();

        let tailer = JsonlTailer::new(source.clone(), offset.clone());
        let mut ids = Vec::new();
        tailer
            .ingest(|value| {
                ids.push(value["id"].as_i64().unwrap());
                Ok(())
            })
            .unwrap();

        assert_eq!(ids, vec![1]);

        let mut file = fs::OpenOptions::new().append(true).open(&source).unwrap();
        file.write_all(b"\n").unwrap();

        let mut resumed = Vec::new();
        tailer
            .ingest(|value| {
                resumed.push(value["id"].as_i64().unwrap());
                Ok(())
            })
            .unwrap();

        assert_eq!(resumed, vec![2]);
    }

    #[test]
    fn same_length_replacement_resets_saved_offset() {
        let dir = tempdir().unwrap();
        let source = dir.path().join("events.jsonl");
        let offset = dir.path().join("events.offset");
        fs::write(&source, b"{\"id\":1}\n").unwrap();

        let tailer = JsonlTailer::new(source.clone(), offset.clone());
        tailer.ingest(|_| Ok(())).unwrap();

        fs::write(&source, b"{\"id\":9}\n").unwrap();

        let mut ids = Vec::new();
        tailer
            .ingest(|value| {
                ids.push(value["id"].as_i64().unwrap());
                Ok(())
            })
            .unwrap();

        assert_eq!(ids, vec![9]);
    }

    #[test]
    fn shorter_truncation_resets_saved_offset() {
        let dir = tempdir().unwrap();
        let source = dir.path().join("events.jsonl");
        let offset = dir.path().join("events.offset");
        fs::write(&source, b"{\"id\":12345}\n").unwrap();

        let tailer = JsonlTailer::new(source.clone(), offset);
        tailer.ingest(|_| Ok(())).unwrap();

        fs::write(&source, b"{\"id\":2}\n").unwrap();

        let mut ids = Vec::new();
        tailer
            .ingest(|value| {
                ids.push(value["id"].as_i64().unwrap());
                Ok(())
            })
            .unwrap();

        assert_eq!(ids, vec![2]);
    }
}
