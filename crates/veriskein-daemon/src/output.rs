use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use anyhow::{Context, Result, anyhow};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use veriskein_alert::{AlertRecord, stdout_sink};
use veriskein_proto::OwnedEvent;

pub fn event_to_alert(
    event: &OwnedEvent,
    ingest_seq: u64,
    workspace: &str,
) -> Result<Option<AlertRecord>> {
    let timestamp = format_timestamp(event)?;
    Ok(AlertRecord::from_exec_event(
        event, ingest_seq, workspace, timestamp,
    ))
}

pub fn open_sink(path: Option<&Path>) -> Result<Box<dyn Write + Send>> {
    match path {
        Some(path) => {
            let file = File::create(path)
                .with_context(|| format!("create alert output file {}", path.display()))?;
            Ok(Box::new(BufWriter::new(file)))
        }
        None => Ok(stdout_sink()),
    }
}

fn format_timestamp(event: &OwnedEvent) -> Result<String> {
    let nanos = i128::from(event.header().ts_ns);
    let dt = OffsetDateTime::from_unix_timestamp_nanos(nanos)
        .map_err(|err| anyhow!("invalid event timestamp: {err}"))?;
    dt.format(&Rfc3339)
        .map_err(|err| anyhow!("format RFC3339 timestamp: {err}"))
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::NamedTempFile;

    use super::open_sink;

    #[test]
    fn sink_writes_file() {
        let file = NamedTempFile::new().expect("temp file");
        let path = file.path().to_path_buf();
        {
            let mut sink = open_sink(Some(&path)).expect("sink should open");
            sink.write_all(b"hello").expect("write");
            sink.flush().expect("flush");
        }
        let contents = std::fs::read_to_string(path).expect("read file");
        assert_eq!(contents, "hello");
    }
}
