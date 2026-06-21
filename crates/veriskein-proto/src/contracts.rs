pub struct RegistryOwner {
    pub registry: &'static str,
    pub writer: &'static str,
}

pub const REGISTRY_OWNERS: &[RegistryOwner] = &[
    RegistryOwner {
        registry: "process/path/fd/mount",
        writer: "veriskein-normalizer",
    },
    RegistryOwner {
        registry: "session/agent/role/workspace",
        writer: "veriskein-graph",
    },
    RegistryOwner {
        registry: "connection/socket",
        writer: "veriskein-state-net",
    },
    RegistryOwner {
        registry: "tls capture attachment",
        writer: "veriskein-bpf",
    },
    RegistryOwner {
        registry: "tls content attribution",
        writer: "veriskein-content",
    },
    RegistryOwner {
        registry: "prompt/artifact/evidence chain",
        writer: "veriskein-correlator",
    },
];

pub struct ReconcilerContract {
    pub name: &'static str,
    pub owner: &'static str,
    pub max_cadence_s: u64,
    pub cache_ttl_s: u64,
    pub produced_facts: &'static [&'static str],
    pub stale_behavior: &'static str,
}

pub const RECONCILERS: &[ReconcilerContract] = &[
    ReconcilerContract {
        name: "startup_proc_merge",
        owner: "veriskein-normalizer",
        max_cadence_s: 0,
        cache_ttl_s: crate::defaults::EXPIRING_PROC_HOLD_MS / 1000,
        produced_facts: &["ProcessSnapshot"],
        stale_behavior: "consume cached snapshot or leave process unattributed",
    },
    ReconcilerContract {
        name: "env_sniff",
        owner: "veriskein-graph",
        max_cadence_s: 0,
        cache_ttl_s: crate::defaults::AGENT_PROMOTION_WINDOW_S,
        produced_facts: &["EnvEvidence"],
        stale_behavior: "treat env evidence as absent",
    },
    ReconcilerContract {
        name: "path_canonicalization",
        owner: "veriskein-normalizer",
        max_cadence_s: 0,
        cache_ttl_s: 0,
        produced_facts: &["PathResolution"],
        stale_behavior: "emit unresolved sensitive path verdict",
    },
    ReconcilerContract {
        name: "template_suppression_maintenance",
        owner: "veriskein-correlator",
        max_cadence_s: 60,
        cache_ttl_s: 300,
        produced_facts: &["SuppressionHint"],
        stale_behavior: "continue matching without suppression hints",
    },
];

pub struct DetectorInputContract {
    pub detector: &'static str,
    pub raw_events: &'static [&'static str],
    pub derived_signals: &'static [&'static str],
    pub chains: bool,
}

pub const DETECTOR_INPUTS: &[DetectorInputContract] = &[
    DetectorInputContract {
        detector: "unexpected_shell",
        raw_events: &["proc_exec"],
        derived_signals: &[],
        chains: false,
    },
    DetectorInputContract {
        detector: "sensitive_file_access",
        raw_events: &["file_open"],
        derived_signals: &["SensitivePathHit"],
        chains: false,
    },
    DetectorInputContract {
        detector: "out_of_workspace_deletion",
        raw_events: &["file_unlink", "file_rename"],
        derived_signals: &["OutOfWorkspaceMutation"],
        chains: false,
    },
    DetectorInputContract {
        detector: "single_agent_deadloop",
        raw_events: &["net_connect", "file_open"],
        derived_signals: &["SessionProgressSignal", "RepeatedPromptSignal"],
        chains: false,
    },
];
