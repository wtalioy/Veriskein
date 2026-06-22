use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::{
    AF_INET_RAW, AF_INET6_RAW, ContentFragEvent, EventHeader, FdDupEvent, FileOpenEvent,
    FileRenameEvent, FileUnlinkEvent, Finding, FindingEvidence, FindingHealth, FindingObjects,
    FindingType, MetaDropEvent, NetConnectEvent, ProcChdirEvent, ProcExecEvent, ProcExitEvent,
    ProcForkEvent, TlsAssocEvent, net_addr_from_raw, raw_net_addr,
};

#[test]
fn raw_net_addr_round_trips_ipv4_and_ipv6_layouts() {
    let ipv4 = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
    let (family, addr) = raw_net_addr(ipv4);
    assert_eq!(family, AF_INET_RAW);
    assert_eq!(&addr[..12], &[0; 12]);
    assert_eq!(net_addr_from_raw(family, addr), Some(ipv4));

    let ipv6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
    let (family, addr) = raw_net_addr(ipv6);
    assert_eq!(family, AF_INET6_RAW);
    assert_eq!(net_addr_from_raw(family, addr), Some(ipv6));
    assert_eq!(net_addr_from_raw(0, addr), None);
}

#[test]
fn wire_event_sizes_are_pinned_to_bpf_abi() {
    assert_eq!(size_of::<EventHeader>(), 88);
    assert_eq!(size_of::<ProcForkEvent>(), 104);
    assert_eq!(size_of::<ProcExecEvent>(), 608);
    assert_eq!(size_of::<ProcExitEvent>(), 96);
    assert_eq!(size_of::<ProcChdirEvent>(), 356);
    assert_eq!(size_of::<FdDupEvent>(), 104);
    assert_eq!(size_of::<FileOpenEvent>(), 380);
    assert_eq!(size_of::<FileUnlinkEvent>(), 360);
    assert_eq!(size_of::<FileRenameEvent>(), 624);
    assert_eq!(size_of::<NetConnectEvent>(), 137);
    assert_eq!(size_of::<ContentFragEvent>(), 3192);
    assert_eq!(size_of::<TlsAssocEvent>(), 112);
    assert_eq!(size_of::<MetaDropEvent>(), 120);
}

#[test]
fn finding_round_trips_from_runtime_json() {
    let mut finding = Finding {
        finding_type: FindingType::CrossAgentPromptInjection,
        ts_ns: 1,
        pid: 2,
        tid: 2,
        session_id: "session".to_string(),
        agent_id: Some("agent".to_string()),
        reason_code: "capi_cross_session_prompt_to_syscall".to_string(),
        summary: "cross-session prompt injection".to_string(),
        process_comm: "agent".to_string(),
        process_binary: "/usr/bin/agent".to_string(),
        workspace: "/tmp/ws".to_string(),
        objects: FindingObjects {
            prompt_ids: vec!["prompt".to_string()],
            artifact_ids: vec!["artifact".to_string()],
            event_ids: vec!["event".to_string()],
            chain_id: Some("chain".to_string()),
            ..FindingObjects::default()
        },
        evidence: vec![FindingEvidence::chain_ref(
            "excerpt_match",
            "chain".to_string(),
            Some(0.4),
            Some("src".to_string()),
            Some("dst".to_string()),
            Some("exact".to_string()),
        )],
        health: FindingHealth::full(),
        component_scores: Default::default(),
        explanation: None,
    };
    finding
        .component_scores
        .insert("causal_score".to_string(), 0.9);

    let json = serde_json::to_string(&finding).expect("serialize finding");
    let parsed: Finding = serde_json::from_str(&json).expect("deserialize finding");

    assert_eq!(parsed.reason_code, finding.reason_code);
    assert_eq!(parsed.evidence[0].kind, "excerpt_match");
    assert_eq!(parsed.component_scores.get("causal_score"), Some(&0.9));
}
