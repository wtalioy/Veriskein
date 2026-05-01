use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use anyhow::{Context, Result};
use veriskein_alert::stdout_sink;

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
