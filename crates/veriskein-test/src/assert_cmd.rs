use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::Value;

pub(crate) fn assert_files(expect: &Path, actual: &Path, timeout: Option<&str>) -> Result<()> {
    let expectations: Vec<veriskein_test::Expectation> = read_ndjson(expect)?;
    let timeout = timeout.map(parse_duration).transpose()?;
    let Some(timeout) = timeout else {
        let actual_values: Vec<Value> = read_ndjson(actual)?;
        return veriskein_test::assert_expectations(&expectations, &actual_values);
    };

    let deadline = Instant::now() + timeout;
    loop {
        match read_ndjson::<Value>(actual).and_then(|actual_values| {
            veriskein_test::assert_expectations(&expectations, &actual_values)
        }) {
            Ok(()) => return Ok(()),
            Err(error) => {
                if Instant::now() >= deadline {
                    return Err(error).context("assertion timed out");
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

fn read_ndjson<T>(path: &Path) -> Result<Vec<T>>
where
    T: for<'de> Deserialize<'de>,
{
    std::fs::read_to_string(path)
        .with_context(|| format!("read ndjson {}", path.display()))?
        .lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(idx, line)| {
            serde_json::from_str(line)
                .with_context(|| format!("parse {} line {}", path.display(), idx + 1))
        })
        .collect()
}

fn parse_duration(text: &str) -> Result<Duration> {
    let Some((number, suffix)) = text
        .strip_suffix("ms")
        .map(|number| (number, "ms"))
        .or_else(|| text.strip_suffix('s').map(|number| (number, "s")))
        .or_else(|| text.strip_suffix('m').map(|number| (number, "m")))
    else {
        bail!("duration {text:?} must use ms, s, or m suffix");
    };
    let amount: u64 = number
        .parse()
        .with_context(|| format!("parse duration {text:?}"))?;
    match suffix {
        "ms" => Ok(Duration::from_millis(amount)),
        "s" => Ok(Duration::from_secs(amount)),
        "m" => Ok(Duration::from_secs(amount * 60)),
        _ => unreachable!("validated suffix"),
    }
}
