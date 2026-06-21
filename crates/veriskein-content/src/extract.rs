use serde_json::Value;
use veriskein_proto::defaults;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PromptCandidate {
    pub text: String,
    pub degradation_reasons: Vec<String>,
}

pub(crate) enum JsonFrame {
    Complete { value: Value, consumed: usize },
    Incomplete,
    NotJson,
}

pub(crate) fn parse_json_frame(bytes: &[u8]) -> JsonFrame {
    let trimmed_start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(0);
    let Some(first) = bytes.get(trimmed_start).copied() else {
        return JsonFrame::Incomplete;
    };
    if !matches!(first, b'{' | b'[' | b'"') {
        return JsonFrame::NotJson;
    }

    let mut stream =
        serde_json::Deserializer::from_slice(&bytes[trimmed_start..]).into_iter::<Value>();
    match stream.next() {
        Some(Ok(value)) => JsonFrame::Complete {
            value,
            consumed: trimmed_start + stream.byte_offset(),
        },
        Some(Err(error)) if error.is_eof() => JsonFrame::Incomplete,
        Some(Err(_)) => JsonFrame::NotJson,
        None => JsonFrame::Incomplete,
    }
}

pub(crate) fn extract_from_body(body: &[u8]) -> Vec<PromptCandidate> {
    let mut degraded = Vec::new();
    let text = match String::from_utf8(body.to_vec()) {
        Ok(text) => text,
        Err(error) => {
            degraded.push("bad_utf8".to_string());
            String::from_utf8_lossy(error.as_bytes()).into_owned()
        }
    };

    let mut candidates = match serde_json::from_str::<Value>(&text) {
        Ok(value) => extract_candidates_from_json(&value, degraded.clone()),
        Err(_) => Vec::new(),
    };

    if candidates.is_empty() && !text.trim().is_empty() {
        degraded.push("fallback_whole_body".to_string());
        candidates.push(finalize_candidate(text, degraded));
    }

    candidates
}

pub(crate) fn extract_candidates_from_json(
    value: &Value,
    degraded: Vec<String>,
) -> Vec<PromptCandidate> {
    extract_from_json(value)
        .into_iter()
        .map(|text| finalize_candidate(text, degraded.clone()))
        .collect()
}

pub(crate) fn extract_from_json(value: &Value) -> Vec<String> {
    let mut out = Vec::new();
    collect_json_prompts(value, &mut out);
    out
}

fn collect_json_prompts(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for key in ["prompt", "input"] {
                if let Some(text) = map.get(key).and_then(Value::as_str) {
                    push_prompt(out, text);
                }
            }

            if let Some(messages) = map.get("messages").and_then(Value::as_array) {
                for message in messages {
                    if let Some(content) = message.get("content") {
                        collect_content_value(content, out);
                    }
                }
            }

            if let Some(arguments) = map.get("arguments").and_then(Value::as_object)
                && let Some(prompt) = arguments.get("prompt").and_then(Value::as_str)
            {
                push_prompt(out, prompt);
            }

            for (key, value) in map {
                if matches!(key.as_str(), "prompt" | "input" | "messages" | "arguments") {
                    continue;
                }
                collect_json_prompts(value, out);
            }
        }
        Value::Array(values) => {
            for value in values {
                collect_json_prompts(value, out);
            }
        }
        _ => {}
    }
}

fn collect_content_value(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::String(text) => push_prompt(out, text),
        Value::Array(parts) => {
            for part in parts {
                if let Some(text) = part.as_str() {
                    push_prompt(out, text);
                } else if let Some(text) = part.get("text").and_then(Value::as_str) {
                    push_prompt(out, text);
                }
            }
        }
        _ => {}
    }
}

fn push_prompt(out: &mut Vec<String>, text: &str) {
    if !text.trim().is_empty() {
        out.push(text.to_string());
    }
}

fn finalize_candidate(text: String, mut degraded: Vec<String>) -> PromptCandidate {
    let (text, truncated) = excerpt(text);
    if truncated {
        degraded.push("truncation".to_string());
    }
    PromptCandidate {
        text,
        degradation_reasons: degraded,
    }
}

fn excerpt(text: String) -> (String, bool) {
    let max = defaults::TEXT_EXCERPT_MAX;
    if text.len() <= max {
        return (text, false);
    }

    let marker = "\n[...truncated...]\n";
    let tail_len = defaults::TEXT_EXCERPT_TAIL.min(max.saturating_sub(marker.len()));
    let head_len = max.saturating_sub(tail_len + marker.len());
    let head_end = floor_char_boundary(&text, head_len);
    let tail_start = ceil_char_boundary(&text, text.len().saturating_sub(tail_len));

    let mut out = String::with_capacity(max);
    out.push_str(&text[..head_end]);
    out.push_str(marker);
    out.push_str(&text[tail_start..]);
    (out, true)
}

fn floor_char_boundary(text: &str, mut index: usize) -> usize {
    index = index.min(text.len());
    while !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}

fn ceil_char_boundary(text: &str, mut index: usize) -> usize {
    index = index.min(text.len());
    while index < text.len() && !text.is_char_boundary(index) {
        index += 1;
    }
    index
}
