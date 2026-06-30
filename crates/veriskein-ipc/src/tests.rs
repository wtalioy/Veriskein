use serde_json::json;

use super::*;

#[test]
fn round_trips_hello_frame_as_ndjson() {
    let mut hello = HelloFrame::new("veriskein-cli");
    hello.client_version = Some("0.1.0".to_string());
    hello.subscriptions = vec![Topic::Alert];

    let frame = IpcFrame::Hello(hello);
    let encoded = encode_ndjson(&frame).expect("encode frame");

    assert!(encoded.ends_with('\n'));
    assert_eq!(encoded.lines().count(), 1);
    let value: serde_json::Value = serde_json::from_str(encoded.trim()).expect("json");
    assert_eq!(value["kind"], "hello");
    assert_eq!(value["subscribe"], json!(["alerts"]));
    assert!(value.get("topic").is_none());
    assert!(value.get("payload").is_none());
    assert_eq!(decode_ndjson(&encoded).expect("decode frame"), frame);
}

#[test]
fn round_trips_welcome_frame_with_default_queue_policy() {
    let mut welcome = WelcomeFrame::new("veriskein-daemon");
    welcome.server_version = Some("0.1.0".to_string());

    let frame = IpcFrame::Welcome(welcome);
    let decoded = decode_ndjson(&encode_ndjson(&frame).expect("encode frame")).expect("decode");
    let value: serde_json::Value =
        serde_json::from_str(encode_ndjson(&frame).expect("encode frame").trim()).expect("json");

    assert_eq!(value["kind"], "welcome");
    assert_eq!(value["run_id"], "unknown");
    assert_eq!(value["schema"]["alert"], SCHEMA_VERSION);
    assert_eq!(value["schema"]["metrics"], SCHEMA_VERSION);
    assert_eq!(decoded, frame);
    assert_eq!(QueuePolicy::default().alerts_capacity, IPC_ALERTS_QUEUE);
    assert_eq!(
        QueuePolicy::default().client_slow_timeout_ms,
        IPC_CLIENT_SLOW_TIMEOUT_MS
    );
    assert_eq!(
        QueuePolicy::default().alerts_overflow,
        QueueOverflowPolicy::DropClientOnLag
    );
}

#[test]
fn round_trips_error_frame() {
    let frame = IpcFrame::Error(ErrorFrame::version_mismatch(999, SCHEMA_VERSION));

    assert_eq!(
        decode_ndjson(&encode_ndjson(&frame).expect("encode frame")).expect("decode"),
        frame
    );
}

#[test]
fn round_trips_alert_frame_with_json_payload() {
    let alert = json!({
        "schema_version": SCHEMA_VERSION,
        "alert_id": "alert-1",
        "type": "unexpected_shell",
        "severity": "high",
        "summary": "shell observed"
    });
    let frame = IpcFrame::Alert(AlertFrame::new(alert));

    assert_eq!(
        decode_ndjson(&encode_ndjson(&frame).expect("encode frame")).expect("decode"),
        frame
    );
}

#[test]
fn round_trips_metrics_frame() {
    let mut metrics = MetricsSnapshot::new(42);
    metrics.counters.insert("alerts_sent".to_string(), 7);
    metrics.gauges.insert("drop_rate".to_string(), 0.25);
    metrics.queue_depths = QueueDepths {
        alerts: 3,
        events: 2,
        graph: 1,
    };
    let frame = IpcFrame::Metrics(MetricsFrame::new(metrics));

    assert_eq!(
        decode_ndjson(&encode_ndjson(&frame).expect("encode frame")).expect("decode"),
        frame
    );
}

#[test]
fn round_trips_event_graph_query_and_reply_frames() {
    let event = IpcFrame::Event(EventFrame::new(
        "evt-1",
        10,
        "proc_exec",
        42,
        Some("session-1".to_string()),
        json!({"argv":["agent"]}),
    ));
    let graph = IpcFrame::Graph(GraphFrame::new(
        11,
        json!({"op":"bind","pid":42,"role":"root_agent"}),
    ));
    let query = IpcFrame::Query(QueryFrame::new("q-1", Topic::Events));
    let reply = IpcFrame::Reply(ReplyFrame::ok(
        "q-1",
        Topic::Events,
        vec![json!({"event_id":"evt-1"})],
    ));
    let dropped = IpcFrame::EventsDropped(EventsDroppedFrame::new(12, 3, "client_lagged"));

    for frame in [event, graph, query, reply, dropped] {
        assert_eq!(
            decode_ndjson(&encode_ndjson(&frame).expect("encode frame")).expect("decode"),
            frame
        );
    }
}

#[test]
fn rejects_ipc_version_mismatch() {
    let mut hello = HelloFrame::new("old-client");
    hello.ipc_version = IPC_VERSION + 1;
    let encoded = serde_json::to_string(&IpcFrame::Hello(hello)).expect("serialize frame");

    let err = decode_ndjson(&encoded).expect_err("version mismatch");

    assert!(matches!(
        err,
        IpcError::VersionMismatch {
            expected_ipc_version: IPC_VERSION,
            received_ipc_version,
            expected_schema_version: SCHEMA_VERSION,
            received_schema_version: SCHEMA_VERSION,
        } if received_ipc_version == IPC_VERSION + 1
    ));
}

#[test]
fn rejects_schema_version_mismatch() {
    let mut metrics = MetricsFrame::new(MetricsSnapshot::new(7));
    metrics.schema_version = SCHEMA_VERSION + 1;
    let encoded = serde_json::to_string(&IpcFrame::Metrics(metrics)).expect("serialize frame");

    let err = decode_ndjson(&encoded).expect_err("schema mismatch");

    assert!(matches!(
        err,
        IpcError::VersionMismatch {
            expected_ipc_version: IPC_VERSION,
            received_ipc_version: IPC_VERSION,
            expected_schema_version: SCHEMA_VERSION,
            received_schema_version,
        } if received_schema_version == SCHEMA_VERSION + 1
    ));
}

#[test]
fn rejects_error_frames_with_mismatched_versions_on_encode() {
    let mut error = ErrorFrame::new(ErrorCode::DecodeError, "bad json");
    error.schema_version = SCHEMA_VERSION + 1;

    let err = encode_ndjson(&IpcFrame::Error(error)).expect_err("schema mismatch");

    assert!(matches!(err, IpcError::VersionMismatch { .. }));
}

#[test]
fn rejects_empty_and_multiline_ndjson() {
    assert!(matches!(decode_ndjson("\n"), Err(IpcError::EmptyLine)));
    assert!(matches!(
        decode_ndjson("{\"topic\":\"hello\"}\n{\"topic\":\"metrics\"}"),
        Err(IpcError::MultilineFrame)
    ));
}

#[test]
fn decodes_minimal_documented_hello_with_provisional_topic() {
    let frame =
        decode_ndjson(r#"{"kind":"hello","ipc_version":1,"subscribe":["alerts","events"]}"#)
            .expect("decode minimal hello");

    let IpcFrame::Hello(hello) = frame else {
        panic!("expected hello");
    };
    assert_eq!(hello.schema_version, SCHEMA_VERSION);
    assert_eq!(hello.client_name, "unknown");
    assert_eq!(hello.subscriptions, vec![Topic::Alert, Topic::Events]);
}
