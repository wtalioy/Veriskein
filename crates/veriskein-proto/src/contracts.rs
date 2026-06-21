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
        registry: "capture attachment/content fd whitelist",
        writer: "veriskein-capture",
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
    pub stale_behavior: &'static str,
}

pub const RECONCILERS: &[ReconcilerContract] = &[
    ReconcilerContract {
        name: "startup_proc_merge",
        owner: "veriskein-normalizer",
        max_cadence_s: 0,
        stale_behavior: "consume cached snapshot or leave process unattributed",
    },
    ReconcilerContract {
        name: "env_sniff",
        owner: "veriskein-graph",
        max_cadence_s: 0,
        stale_behavior: "treat env evidence as absent",
    },
    ReconcilerContract {
        name: "tls_maps_scan",
        owner: "veriskein-capture",
        max_cadence_s: crate::defaults::TLS_ATTACH_RESCAN_S,
        stale_behavior: "mark capture visibility unavailable",
    },
    ReconcilerContract {
        name: "path_canonicalization",
        owner: "veriskein-normalizer",
        max_cadence_s: 0,
        stale_behavior: "emit unresolved sensitive path verdict",
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
        derived_signals: &["SessionProgressSignal"],
        chains: false,
    },
];

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{DETECTOR_INPUTS, RECONCILERS, REGISTRY_OWNERS};

    #[test]
    fn each_registry_has_one_writer() {
        let mut registries = BTreeSet::new();
        for owner in REGISTRY_OWNERS {
            assert!(
                registries.insert(owner.registry),
                "duplicate registry owner"
            );
            assert!(owner.writer.starts_with("veriskein-"));
        }
    }

    #[test]
    fn reconciler_contracts_have_degrade_behavior() {
        for reconciler in RECONCILERS {
            assert!(!reconciler.owner.is_empty());
            assert!(!reconciler.stale_behavior.is_empty());
        }
    }

    #[test]
    fn detector_input_contract_mentions_deadloop_signals() {
        let deadloop = DETECTOR_INPUTS
            .iter()
            .find(|entry| entry.detector == "single_agent_deadloop")
            .expect("deadloop contract");
        assert!(deadloop.raw_events.contains(&"net_connect"));
        assert!(deadloop.derived_signals.contains(&"SessionProgressSignal"));
        assert!(!deadloop.chains);
    }
}
