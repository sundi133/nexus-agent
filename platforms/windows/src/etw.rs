use ferrisetw::{
    parser::Parser,
    provider::Provider,
    schema_locator::SchemaLocator,
    trace::UserTrace,
    EventRecord,
};
use std::sync::mpsc::Sender;

const PROCESS_PROVIDER_GUID: &str = "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716";
const PROCESS_START_EVENT_ID: u16 = 1;

#[derive(Debug, Clone)]
pub struct EtwProcessStart {
    pub pid: u32,
    pub parent_pid: u32,
    pub image_name: String,
}

pub struct ProcessTrace {
    _trace: UserTrace,
}

impl ProcessTrace {
    pub fn start(sender: Sender<EtwProcessStart>) -> Result<Self, String> {
        let callback = move |record: &EventRecord, schema_locator: &SchemaLocator| {
            if record.event_id() != PROCESS_START_EVENT_ID {
                return;
            }

            let Ok(schema) = schema_locator.event_schema(record) else {
                return;
            };
            let parser = Parser::create(record, &schema);

            let Ok(pid) = parser.try_parse::<u32>("ProcessID") else {
                return;
            };
            let parent_pid = parser
                .try_parse::<u32>("ParentProcessID")
                .unwrap_or_default();
            let image_name = parser
                .try_parse::<String>("ImageName")
                .unwrap_or_default();

            let _ = sender.send(EtwProcessStart {
                pid,
                parent_pid,
                image_name,
            });
        };

        let provider = Provider::by_guid(PROCESS_PROVIDER_GUID)
            .add_callback(callback)
            .build();

        let trace = UserTrace::new()
            .named("VotalNexusProcessTrace".to_string())
            .enable(provider)
            .start_and_process()
            .map_err(|error| format!("{error:?}"))?;

        Ok(Self { _trace: trace })
    }
}
