use veriskein_proto::{VisibilityState, defaults};

use crate::{
    ContentChannel, ContentDirection, ContentFragment, ContentRuntime, StreamOwner,
    StreamProvenance,
};

fn owner() -> StreamOwner {
    StreamOwner::new(None, None)
}

fn provenance() -> StreamProvenance {
    StreamProvenance {
        channel: ContentChannel::Tls,
        direction: ContentDirection::Write,
        source: None,
    }
}

fn fragment(stream_id: u64, offset: u64, bytes: impl Into<Vec<u8>>) -> ContentFragment {
    ContentFragment::with_degradation(stream_id, offset, bytes, owner(), provenance(), Vec::new())
}

fn fragment_with_source(
    stream_id: u64,
    offset: u64,
    bytes: impl Into<Vec<u8>>,
    source: &str,
) -> ContentFragment {
    let mut provenance = provenance();
    provenance.source = Some(source.to_string());
    ContentFragment::with_degradation(stream_id, offset, bytes, owner(), provenance, Vec::new())
}

#[test]
fn http_reassembly_split_fragments() {
    let mut runtime = ContentRuntime::new();
    let body = br#"{"prompt":"split hello"}"#;
    let request = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        String::from_utf8_lossy(body)
    );
    let request = request.as_bytes();

    assert!(runtime.append(fragment(7, 35, &request[35..])).is_empty());
    let prompts = runtime.append(fragment(7, 0, &request[..35]));

    assert_eq!(prompts.len(), 1);
    assert_eq!(prompts[0].text, "split hello");
    assert_eq!(prompts[0].visibility, VisibilityState::Full);
}

#[test]
fn json_split() {
    let mut runtime = ContentRuntime::new();
    let first = br#"{"messages":[{"role":"user","content":"hel"#;
    let second = br#"lo from json"}]}"#;

    assert!(runtime.append(fragment(11, 0, first)).is_empty());
    let prompts = runtime.append(fragment(11, first.len() as u64, second));

    assert_eq!(prompts.len(), 1);
    assert_eq!(prompts[0].text, "hello from json");
    assert_eq!(prompts[0].visibility, VisibilityState::Full);
}

#[test]
fn overlapping_streams_do_not_merge() {
    let mut runtime = ContentRuntime::new();
    let one = br#"{"prompt":"stream one"}"#;
    let two = br#"{"prompt":"stream two"}"#;

    let first = runtime.append(fragment(1, 0, one));
    let second = runtime.append(fragment(2, 0, two));

    assert_eq!(first.len(), 1);
    assert_eq!(second.len(), 1);
    assert_eq!(first[0].text, "stream one");
    assert_eq!(second[0].text, "stream two");
    assert_eq!(first[0].stream_id, 1);
    assert_eq!(second[0].stream_id, 2);

    let mut conflict_runtime = ContentRuntime::new();
    assert!(
        conflict_runtime
            .append(fragment(5, 0, b"plain "))
            .is_empty()
    );
    assert!(
        conflict_runtime
            .append(fragment(5, 0, b"other "))
            .is_empty()
    );
    assert!(
        conflict_runtime
            .append(fragment(5, 6, b"prompt"))
            .is_empty()
    );
    let conflicted = conflict_runtime.finish_stream(5);
    assert_eq!(conflicted.len(), 1);
    assert_eq!(conflicted[0].text, "plain prompt");
    assert_eq!(conflicted[0].visibility, VisibilityState::Partial);
    assert!(
        conflicted[0]
            .degradation_reasons
            .iter()
            .any(|reason| reason == "overlap_conflict")
    );
}

#[test]
fn duplicate_overlap_is_accepted() {
    let mut runtime = ContentRuntime::new();
    let first = br#"{"prompt":"dup"#;
    let second = br#"licate"}"#;

    assert!(runtime.append(fragment(12, 0, first)).is_empty());
    assert!(runtime.append(fragment(12, 0, first)).is_empty());
    let prompts = runtime.append(fragment(12, first.len() as u64, second));

    assert_eq!(prompts.len(), 1);
    assert_eq!(prompts[0].text, "duplicate");
    assert_eq!(prompts[0].visibility, VisibilityState::Full);
}

#[test]
fn source_only_provenance_changes_do_not_degrade_content() {
    let mut runtime = ContentRuntime::new();
    let first = br#"{"prompt":"source "#;
    let second = br#"changes"}"#;

    assert!(
        runtime
            .append(fragment_with_source(14, 0, first, "ssl_ctx=abc"))
            .is_empty()
    );
    let prompts = runtime.append(fragment_with_source(
        14,
        first.len() as u64,
        second,
        "ssl_ctx=abc;dst=127.0.0.1:443",
    ));

    assert_eq!(prompts.len(), 1);
    assert_eq!(prompts[0].text, "source changes");
    assert_eq!(prompts[0].visibility, VisibilityState::Full);
    assert!(prompts[0].degradation_reasons.is_empty());
}

#[test]
fn bad_utf8_degrades() {
    let mut runtime = ContentRuntime::new();
    let prompts = runtime.finish_stream(3);
    assert!(prompts.is_empty());

    let prompts = runtime.append(fragment(
        3,
        0,
        b"POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nhi\xff!",
    ));

    assert_eq!(prompts.len(), 1);
    assert_eq!(prompts[0].visibility, VisibilityState::Partial);
    assert!(
        prompts[0]
            .degradation_reasons
            .iter()
            .any(|reason| reason == "bad_utf8")
    );
}

#[test]
fn truncation_head_tail() {
    let mut runtime = ContentRuntime::new();
    let long = format!(
        "{}{}{}",
        "head-",
        "x".repeat(defaults::TEXT_EXCERPT_MAX + 1024),
        "-tail"
    );
    let body = serde_json::json!({ "prompt": long }).to_string();
    let prompts = runtime.append(fragment(9, 0, body.as_bytes()));

    assert_eq!(prompts.len(), 1);
    assert_eq!(prompts[0].visibility, VisibilityState::Partial);
    assert!(prompts[0].text.len() <= defaults::TEXT_EXCERPT_MAX);
    assert!(prompts[0].text.starts_with("head-"));
    assert!(prompts[0].text.ends_with("-tail"));
    assert!(
        prompts[0]
            .degradation_reasons
            .iter()
            .any(|reason| reason == "truncation")
    );
}

#[test]
fn json_prompt_fields_are_not_extracted_twice() {
    let mut runtime = ContentRuntime::new();
    let body = br#"{"messages":[{"role":"user","content":"hello once"}],"arguments":{"prompt":"tool prompt"}}"#;
    let prompts = runtime.append(fragment(13, 0, body));

    let texts = prompts
        .iter()
        .map(|prompt| prompt.text.as_str())
        .collect::<Vec<_>>();
    assert_eq!(texts, vec!["hello once", "tool prompt"]);
}

#[test]
fn tls_stream_key_is_stable_and_direction_scoped() {
    let write = crate::TlsStreamKey::new(10, 0xabc, ContentDirection::Write).stream_id();
    let write_again = crate::TlsStreamKey::new(10, 0xabc, ContentDirection::Write).stream_id();
    let read = crate::TlsStreamKey::new(10, 0xabc, ContentDirection::Read).stream_id();

    assert_eq!(write, write_again);
    assert_ne!(write, read);
}
