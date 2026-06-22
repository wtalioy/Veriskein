#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "common.h"

#define EVT_CONTENT_FRAG 30
#define CONTENT_CHANNEL_STDIO 2
#define CONTENT_CHANNEL_PIPE 3
#define CONTENT_CHANNEL_MCP 4
#define CONTENT_DIRECTION_READ 1
#define CONTENT_DIRECTION_WRITE 2
#define CONTENT_FLAG_TRUNCATED 1

struct content_frag_event {
    struct event_header header;
    __u64 ssl_ctx;
    __u64 stream_offset;
    __u32 byte_len;
    __u32 frag_len;
    __u8 channel;
    __u8 direction;
    __u16 flags;
    __u32 _reserved;
    char data[CONTENT_INLINE_MAX];
} __attribute__((packed));

struct fd_capture_key {
    __u32 tgid;
    __s32 fd;
};

struct fd_capture_policy {
    __u8 channel;
    __u8 _reserved[7];
    __u64 expires_at_ns;
};

struct fd_io_args {
    __s32 fd;
    void *buf;
    __u64 count;
};

struct fd_stream_key {
    __u32 tgid;
    __s32 fd;
    __u8 channel;
    __u8 direction;
    __u16 _pad0;
    __u32 _pad1;
};

VERISKEIN_EVENT_MAPS

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct fd_capture_key);
    __type(value, struct fd_capture_policy);
} fd_capture_whitelist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, PENDING_ARGS_MAX_ENTRIES);
    __type(key, __u32);
    __type(value, struct fd_io_args);
} read_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, STREAM_OFFSETS_MAX_ENTRIES);
    __type(key, struct fd_stream_key);
    __type(value, __u64);
} fd_stream_offsets SEC(".maps");

static __always_inline int valid_channel(__u8 channel)
{
    return channel == CONTENT_CHANNEL_STDIO || channel == CONTENT_CHANNEL_PIPE ||
           channel == CONTENT_CHANNEL_MCP;
}

static __always_inline struct fd_capture_policy *lookup_policy(struct fd_capture_key *key)
{
    struct fd_capture_policy *policy = bpf_map_lookup_elem(&fd_capture_whitelist, key);
    __u64 now = bpf_ktime_get_ns();

    if (!policy) {
        return 0;
    }
    if (!valid_channel(policy->channel)) {
        return 0;
    }
    if (policy->expires_at_ns != 0 && policy->expires_at_ns < now) {
        bpf_map_delete_elem(&fd_capture_whitelist, key);
        return 0;
    }
    return policy;
}

static __always_inline __u64 fd_stream_handle(__u32 tgid, __s32 fd, __u8 channel)
{
    return ((__u64)tgid << 32) ^ ((__u32)fd) ^ ((__u64)channel << 56);
}

static __always_inline __u64 reserve_fd_stream_offset(__u32 tgid, __s32 fd, __u8 channel,
                                                       __u8 direction, __u32 byte_len)
{
    struct fd_stream_key key = {
        .tgid = tgid,
        .fd = fd,
        .channel = channel,
        .direction = direction,
    };
    __u64 zero = 0;
    __u64 *offset = bpf_map_lookup_elem(&fd_stream_offsets, &key);
    __u64 current = 0;

    if (!offset) {
        bpf_map_update_elem(&fd_stream_offsets, &key, &zero, BPF_NOEXIST);
        offset = bpf_map_lookup_elem(&fd_stream_offsets, &key);
    }
    if (offset) {
        current = *offset;
        *offset += byte_len;
    }
    return current;
}

static __always_inline int emit_fd_content(struct fd_capture_key *key,
                                           struct fd_capture_policy *policy, const void *buf,
                                           __u64 len, __u8 direction)
{
    struct content_frag_event *evt;
    __u32 frag_len = len > CONTENT_INLINE_MAX ? CONTENT_INLINE_MAX : (__u32)len;

    if (!buf || len == 0 || key->fd < 0) {
        return 0;
    }
    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) {
        return 0;
    }
    fill_header(&seqs, &evt->header, EVT_CONTENT_FRAG, sizeof(*evt), 0);
    evt->ssl_ctx = fd_stream_handle(key->tgid, key->fd, policy->channel);
    evt->stream_offset =
        reserve_fd_stream_offset(key->tgid, key->fd, policy->channel, direction, (__u32)len);
    evt->byte_len = (__u32)len;
    evt->frag_len = frag_len;
    evt->channel = policy->channel;
    evt->direction = direction;
    evt->flags = len > CONTENT_INLINE_MAX ? CONTENT_FLAG_TRUNCATED : 0;
    evt->_reserved = 0;
    bpf_probe_read_user(&evt->data, frag_len, buf);
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int handle_enter_read(struct sys_enter_args *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    struct fd_capture_key key = {
        .tgid = (__u32)(pid_tgid >> 32),
        .fd = (__s32)ctx->args[0],
    };
    struct fd_capture_policy *policy = lookup_policy(&key);
    struct fd_io_args args = {
        .fd = key.fd,
        .buf = (void *)ctx->args[1],
        .count = (__u64)ctx->args[2],
    };

    if (!policy) {
        return 0;
    }
    bpf_map_update_elem(&read_args, &tid, &args, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int handle_exit_read(struct sys_exit_args *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    struct fd_io_args *args = bpf_map_lookup_elem(&read_args, &tid);
    struct fd_capture_key key = {
        .tgid = (__u32)(pid_tgid >> 32),
    };
    struct fd_capture_policy *policy;

    if (!args) {
        return 0;
    }
    key.fd = args->fd;
    policy = lookup_policy(&key);
    if (policy && ctx->ret > 0) {
        emit_fd_content(&key, policy, args->buf, (__u64)ctx->ret, CONTENT_DIRECTION_READ);
    }
    bpf_map_delete_elem(&read_args, &tid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int handle_enter_write(struct sys_enter_args *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct fd_capture_key key = {
        .tgid = (__u32)(pid_tgid >> 32),
        .fd = (__s32)ctx->args[0],
    };
    struct fd_capture_policy *policy = lookup_policy(&key);

    if (!policy) {
        return 0;
    }
    return emit_fd_content(&key, policy, (const void *)ctx->args[1], (__u64)ctx->args[2],
                           CONTENT_DIRECTION_WRITE);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
