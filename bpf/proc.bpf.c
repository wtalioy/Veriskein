#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define EVT_ABI_VERSION 1
#define EVT_PROC_EXEC 1
#define TASK_COMM_LEN 16
#define PATH_INLINE_MAX 256
#define ARGV_INLINE_MAX 256

struct event_header {
    __u32 abi_version;
    __u16 kind;
    __u16 header_len;
    __u32 total_len;
    __u32 cpu;
    __u64 seq;
    __u64 ts_ns;
} __attribute__((packed));

struct proc_exec_event {
    struct event_header header;
    __u32 pid;
    __u32 tgid;
    __u32 ppid;
    __u64 mount_ns;
    char comm[TASK_COMM_LEN];
    char filename[PATH_INLINE_MAX];
    char argv[ARGV_INLINE_MAX];
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} seqs SEC(".maps");

static __always_inline __u64 next_seq(void)
{
    __u32 key = 0;
    __u64 init = 0;
    __u64 *seq = bpf_map_lookup_elem(&seqs, &key);
    if (!seq) {
        bpf_map_update_elem(&seqs, &key, &init, BPF_ANY);
        seq = bpf_map_lookup_elem(&seqs, &key);
        if (!seq) {
            return 0;
        }
    }

    *seq += 1;
    return *seq;
}

SEC("tracepoint/sched/sched_process_exec")
int handle_sched_process_exec(void *ctx)
{
    struct proc_exec_event *evt;
    __u64 pid_tgid;

    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) {
        return 0;
    }

    __builtin_memset(evt, 0, sizeof(*evt));

    pid_tgid = bpf_get_current_pid_tgid();
    evt->pid = (__u32)pid_tgid;
    evt->tgid = (__u32)(pid_tgid >> 32);
    evt->ppid = 0;
    evt->mount_ns = 0;

    evt->header.abi_version = EVT_ABI_VERSION;
    evt->header.kind = EVT_PROC_EXEC;
    evt->header.header_len = sizeof(struct event_header);
    evt->header.total_len = sizeof(*evt);
    evt->header.cpu = bpf_get_smp_processor_id();
    evt->header.seq = next_seq();
    evt->header.ts_ns = bpf_ktime_get_ns();

    /* Phase 0 captures the thinnest viable exec signal. The filename/argv slots
     * intentionally carry placeholder comm data here; userspace later upgrades
     * fidelity from /proc while the wire ABI stays stable.
     */
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    bpf_get_current_comm(&evt->filename, sizeof(evt->filename));
    bpf_get_current_comm(&evt->argv, sizeof(evt->argv));

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
