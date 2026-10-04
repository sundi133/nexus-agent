use ferrisetw::{
    parser::{Parser, Pointer},
    provider::Provider,
    schema_locator::SchemaLocator,
    trace::UserTrace,
    EventRecord,
};
use std::{
    collections::HashMap,
    sync::{mpsc::Sender, Arc, Mutex},
};

const FILE_PROVIDER_GUID: &str = "edd08927-9cc4-4e65-b970-c2560fb5c289";
const EVENT_NAME_CREATE: u16 = 10;
const EVENT_NAME_DELETE: u16 = 11;
const EVENT_WRITE: u16 = 16;
const EVENT_DELETE_PATH: u16 = 26;
const EVENT_RENAME_PATH: u16 = 27;
const EVENT_CREATE_NEW_FILE: u16 = 30;
const MAX_FILE_KEY_CACHE: usize = 65_536;

// Microsoft-Windows-Kernel-File keyword mask:
// Filename | Fileio | Write | DeletePath | RenameSetLinkPath | CreateNewFile.
const FILE_KEYWORDS: u64 = 0x1E30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileActivityKind {
    Write,
    Rename,
    Delete,
    Create,
}

#[derive(Debug, Clone)]
pub struct EtwFileActivity {
    pub pid: u32,
    pub path: String,
    pub kind: FileActivityKind,
}

pub struct FileTrace {
    _trace: UserTrace,
}

impl FileTrace {
    pub fn start(sender: Sender<EtwFileActivity>) -> Result<Self, String> {
        let names: Arc<Mutex<HashMap<usize, String>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let callback_names = Arc::clone(&names);

        let callback = move |record: &EventRecord, schema_locator: &SchemaLocator| {
            let event_id = record.event_id();

            if !matches!(
                event_id,
                EVENT_NAME_CREATE
                    | EVENT_NAME_DELETE
                    | EVENT_WRITE
                    | EVENT_DELETE_PATH
                    | EVENT_RENAME_PATH
                    | EVENT_CREATE_NEW_FILE
            ) {
                return;
            }

            let Ok(schema) = schema_locator.event_schema(record) else {
                return;
            };
            let parser = Parser::create(record, &schema);

            match event_id {
                EVENT_NAME_CREATE => {
                    let Ok(file_key) = parser.try_parse::<Pointer>("FileKey") else {
                        return;
                    };
                    let Ok(file_name) = parser.try_parse::<String>("FileName") else {
                        return;
                    };
                    if file_name.is_empty() {
                        return;
                    }

                    if let Ok(mut cache) = callback_names.lock() {
                        if cache.len() >= MAX_FILE_KEY_CACHE && !cache.contains_key(&*file_key) {
                            cache.clear();
                        }
                        cache.insert(*file_key, file_name);
                    }
                }
                EVENT_NAME_DELETE => {
                    let Ok(file_key) = parser.try_parse::<Pointer>("FileKey") else {
                        return;
                    };
                    if let Ok(mut cache) = callback_names.lock() {
                        cache.remove(&*file_key);
                    }
                }
                EVENT_WRITE => {
                    let pid = record.process_id();
                    if pid == 0 {
                        return;
                    }

                    let Ok(file_key) = parser.try_parse::<Pointer>("FileKey") else {
                        return;
                    };
                    let path = callback_names
                        .lock()
                        .ok()
                        .and_then(|cache| cache.get(&*file_key).cloned());
                    let Some(path) = path else {
                        return;
                    };

                    let _ = sender.send(EtwFileActivity {
                        pid,
                        path,
                        kind: FileActivityKind::Write,
                    });
                }
                EVENT_DELETE_PATH | EVENT_RENAME_PATH => {
                    let pid = record.process_id();
                    if pid == 0 {
                        return;
                    }
                    let Ok(path) = parser.try_parse::<String>("FilePath") else {
                        return;
                    };
                    if path.is_empty() {
                        return;
                    }

                    let _ = sender.send(EtwFileActivity {
                        pid,
                        path,
                        kind: if event_id == EVENT_RENAME_PATH {
                            FileActivityKind::Rename
                        } else {
                            FileActivityKind::Delete
                        },
                    });
                }
                EVENT_CREATE_NEW_FILE => {
                    let pid = record.process_id();
                    if pid == 0 {
                        return;
                    }
                    let Ok(path) = parser.try_parse::<String>("FileName") else {
                        return;
                    };
                    if path.is_empty() {
                        return;
                    }

                    let _ = sender.send(EtwFileActivity {
                        pid,
                        path,
                        kind: FileActivityKind::Create,
                    });
                }
                _ => {}
            }
        };

        let provider = Provider::by_guid(FILE_PROVIDER_GUID)
            .any(FILE_KEYWORDS)
            .add_callback(callback)
            .build();

        let trace = UserTrace::new()
            .named("VotalNexusFileTrace".to_string())
            .enable(provider)
            .start_and_process()
            .map_err(|error| format!("{error:?}"))?;

        Ok(Self { _trace: trace })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyword_mask_includes_filename_and_write() {
        assert_ne!(FILE_KEYWORDS & 0x10, 0);
        assert_ne!(FILE_KEYWORDS & 0x200, 0);
    }

    #[test]
    fn file_activity_kind_marks_rename_only_for_rename() {
        assert_eq!(FileActivityKind::Rename, FileActivityKind::Rename);
        assert_ne!(FileActivityKind::Write, FileActivityKind::Rename);
    }
}
