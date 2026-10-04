use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fs,
    io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write},
    path::PathBuf,
};

const MAX_LINE_BYTES: usize = 1024 * 1024;
const MAX_RECORDS_PER_CYCLE: usize = 4096;
const CHECKPOINT_PREFIX_BYTES: usize = 256;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IngestStats {
    pub records: usize,
    pub invalid_records: usize,
    pub bytes_advanced: u64,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
struct TailCheckpoint {
    offset: u64,
    prefix_len: usize,
    prefix_hash: u64,
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
        let checkpoint = self.read_checkpoint()?.unwrap_or_default();

        let fingerprint_matches = if checkpoint.offset == 0 || checkpoint.prefix_len == 0 {
            true
        } else {
            prefix_fingerprint(&file, checkpoint.prefix_len)?
                .is_some_and(|hash| hash == checkpoint.prefix_hash)
        };

        let offset = if checkpoint.offset > source_len || !fingerprint_matches {
            0
        } else {
            checkpoint.offset
        };

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
            let prefix_len = committed_offset.min(CHECKPOINT_PREFIX_BYTES as u64) as usize;
            let prefix_hash =
                prefix_fingerprint(reader.get_ref(), prefix_len)?.unwrap_or_default();

            self.write_checkpoint(TailCheckpoint {
                offset: committed_offset,
                prefix_len,
                prefix_hash,
            })?;
            stats.bytes_advanced = committed_offset.saturating_sub(offset);
        }

        Ok(stats)
    }

    fn read_checkpoint(&self) -> io::Result<Option<TailCheckpoint>> {
        match fs::read_to_string(&self.offset_path) {
            Ok(value) => {
                if let Ok(checkpoint) = serde_json::from_str::<TailCheckpoint>(&value) {
                    return Ok(Some(checkpoint));
                }

                // Backward compatibility with the original plain integer offset.
                Ok(value.trim().parse::<u64>().ok().map(|offset| TailCheckpoint {
                    offset,
                    prefix_len: 0,
                    prefix_hash: 0,
                }))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn write_checkpoint(&self, checkpoint: TailCheckpoint) -> io::Result<()> {
        if let Some(parent) = self.offset_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let file_name = self
            .offset_path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("events.offset");
        let tmp = self.offset_path.with_file_name(format!(".{file_name}.tmp"));

        {
            let mut file = fs::File::create(&tmp)?;
            serde_json::to_writer(&mut file, &checkpoint)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            file.write_all(b"\n")?;
            file.sync_all()?;
        }

        fs::rename(tmp, &self.offset_path)
    }
}

fn prefix_fingerprint(file: &fs::File, prefix_len: usize) -> io::Result<Option<u64>> {
    if prefix_len == 0 {
        return Ok(None);
    }

    let mut clone = file.try_clone()?;
    clone.seek(SeekFrom::Start(0))?;

    let mut remaining = prefix_len;
    let mut buffer = [0u8; CHECKPOINT_PREFIX_BYTES];
    let mut hash = 0xcbf29ce484222325u64;

    while remaining > 0 {
        let take = remaining.min(buffer.len());
        let read = clone.read(&mut buffer[..take])?;
        if read == 0 {
            return Ok(None);
        }

        for byte in &buffer[..read] {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
        remaining -= read;
    }

    Ok(Some(hash))
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

        let tailer = JsonlTailer::new(source.clone(), offset);
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

        let tailer = JsonlTailer::new(source.clone(), offset);
        tailer.ingest(|_| Ok(())).unwrap();

        // Same byte length as the original file: offset alone cannot detect replacement.
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
    fn append_preserves_checkpoint_prefix() {
        let dir = tempdir().unwrap();
        let source = dir.path().join("events.jsonl");
        let offset = dir.path().join("events.offset");
        fs::write(&source, b"{\"id\":1}\n").unwrap();

        let tailer = JsonlTailer::new(source.clone(), offset);
        tailer.ingest(|_| Ok(())).unwrap();

        let mut file = fs::OpenOptions::new().append(true).open(&source).unwrap();
        file.write_all(b"{\"id\":2}\n").unwrap();

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
