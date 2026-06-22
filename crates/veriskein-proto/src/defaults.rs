pub const EVT_ABI_VERSION: u32 = 2;
pub const ALERT_SCHEMA_VERSION: u32 = 1;
pub const IPC_SCHEMA_VERSION: u32 = 1;
pub const NS_PER_MS: u64 = 1_000_000;
pub const NS_PER_SEC: u64 = 1_000_000_000;

pub const fn ms_to_ns(ms: u64) -> u64 {
    ms * NS_PER_MS
}

pub const fn secs_to_ns(secs: u64) -> u64 {
    secs * NS_PER_SEC
}

// These inline capacities must stay in lockstep with the BPF-side structs.
pub const TASK_COMM_LEN: usize = 16;
pub const PATH_INLINE_MAX: usize = 256;
pub const ARGV_INLINE_MAX: usize = 256;
pub const CONTENT_INLINE_MAX: usize = 3072;
pub const TEXT_EXCERPT_MAX: usize = 4096;
pub const TEXT_EXCERPT_TAIL: usize = 512;
pub const RINGBUF_SIZE_TOTAL: usize = 16 * 1024 * 1024;
pub const RINGBUF_POLL_INTERVAL_MS: u64 = 1;
pub const SYMLINK_MAX_DEPTH: u8 = 16;
pub const EXPIRING_PROC_HOLD_MS: u64 = 30_000;
pub const PROMPT_WINDOW_MS: u64 = 60_000;
pub const CAPI_WINDOW_MS: u64 = 300_000;
pub const AGENT_PROMOTION_WINDOW_S: u64 = 5;
pub const LLM_ENDPOINT_DNS_REFRESH_S: u64 = 600;
pub const MINHASH_NPERM: usize = 64;
pub const NEAR_EXACT_JACCARD: f32 = 0.60;
pub const CAPI_SCORE_THRESHOLD: f32 = 0.70;
pub const DEADLOOP_WINDOW_S: u64 = 120;
pub const DEADLOOP_CONNECT_RATE_PMIN: u32 = 30;
pub const DEADLOOP_PROMPT_DUP: u32 = 5;
pub const DEADLOOP_FILE_REPEAT: u32 = 20;
pub const ALERT_DEDUP_SECS: u64 = 60;
pub const DEADLOOP_ALERT_COOLDOWN_S: u64 = 600;
pub const DROP_RATE_DEGRADE_THRESHOLD: f32 = 0.01;
pub const SESSION_DRAIN_SECS: u64 = 300;
pub const MAX_PROCESS_STATES: usize = 200_000;
pub const MAX_STREAMS: usize = 16_384;
pub const MAX_PROMPTS: usize = 32_768;
pub const MAX_ARTIFACTS: usize = 32_768;
pub const MAX_EVENT_INDEX: usize = 250_000;
pub const MAX_TEMPLATE_IGNORE: usize = 10_000;
pub const MAX_ALERT_THROTTLE_ENTRIES: usize = 16_384;
pub const MAX_DEADLOOP_SESSIONS: usize = 16_384;
pub const IPC_VERSION: u32 = 1;
pub const IPC_ALERTS_QUEUE: usize = 1024;
pub const IPC_CLIENT_SLOW_TIMEOUT_MS: u64 = 2_000;
