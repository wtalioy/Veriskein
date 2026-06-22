#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "common.h"

#define EVT_CONTENT_FRAG 30
#define EVT_TLS_ASSOC 31
#define CONTENT_INLINE_MAX 3072
#define CONTENT_CHANNEL_TLS 1
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

struct tls_assoc_event {
    struct event_header header;
    __u64 ssl_ctx;
    __s32 fd;
    __s32 assoc_ret;
    __u8 direction;
    __u8 _reserved[7];
} __attribute__((packed));

struct ssl_read_args {
    void *ssl;
    void *buf;
    __u64 requested;
    void *out_len;
};

struct ssl_assoc_args {
    void *ssl;
    __s32 fd;
    __u8 direction;
    __u8 _pad0;
    __u16 _pad1;
};

struct stream_key {
    __u32 tgid;
    __u64 ssl_ctx;
    __u8 direction;
    __u8 _pad0;
    __u16 _pad1;
};

struct pt_regs_x86_64 {
    unsigned long r15;
    unsigned long r14;
    unsigned long r13;
    unsigned long r12;
    unsigned long bp;
    unsigned long bx;
    unsigned long r11;
    unsigned long r10;
    unsigned long r9;
    unsigned long r8;
    unsigned long ax;
    unsigned long cx;
    unsigned long dx;
    unsigned long si;
    unsigned long di;
    unsigned long orig_ax;
    unsigned long ip;
    unsigned long cs;
    unsigned long flags;
    unsigned long sp;
    unsigned long ss;
};

#define VSK_PARM1(ctx) (((struct pt_regs_x86_64 *)(ctx))->di)
#define VSK_PARM2(ctx) (((struct pt_regs_x86_64 *)(ctx))->si)
#define VSK_PARM3(ctx) (((struct pt_regs_x86_64 *)(ctx))->dx)
#define VSK_RC(ctx) (((struct pt_regs_x86_64 *)(ctx))->ax)

VERISKEIN_EVENT_MAPS

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, struct ssl_read_args);
} ssl_read_args_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, struct ssl_assoc_args);
} ssl_assoc_args_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct stream_key);
    __type(value, __u64);
} stream_offsets SEC(".maps");

static __always_inline __u64 reserve_stream_offset(void *ssl, __u8 direction, __u32 byte_len)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct stream_key key = {
        .tgid = (__u32)(pid_tgid >> 32),
        .ssl_ctx = (__u64)ssl,
        .direction = direction,
    };
    __u64 zero = 0;
    __u64 *offset = bpf_map_lookup_elem(&stream_offsets, &key);
    __u64 current = 0;

    if (!offset) {
        bpf_map_update_elem(&stream_offsets, &key, &zero, BPF_NOEXIST);
        offset = bpf_map_lookup_elem(&stream_offsets, &key);
    }
    if (offset) {
        current = *offset;
        *offset += byte_len;
    }
    return current;
}

static __always_inline int emit_content_frag(void *ssl, const void *buf, __u64 len, __u8 direction)
{
    struct content_frag_event *evt;
    __u32 frag_len = len > CONTENT_INLINE_MAX ? CONTENT_INLINE_MAX : (__u32)len;

    if (!buf || len == 0) {
        return 0;
    }

    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) {
        return 0;
    }
    fill_header(&seqs, &evt->header, EVT_CONTENT_FRAG, sizeof(*evt), 0);
    evt->ssl_ctx = (__u64)ssl;
    evt->stream_offset = reserve_stream_offset(ssl, direction, (__u32)len);
    evt->byte_len = (__u32)len;
    evt->frag_len = frag_len;
    evt->channel = CONTENT_CHANNEL_TLS;
    evt->direction = direction;
    evt->flags = len > CONTENT_INLINE_MAX ? CONTENT_FLAG_TRUNCATED : 0;
    evt->_reserved = 0;
    bpf_probe_read_user(&evt->data, frag_len, buf);
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

static __always_inline int emit_tls_assoc(void *ssl, __s32 fd, __s32 ret, __u8 direction)
{
    struct tls_assoc_event *evt;

    if (!ssl || fd < 0 || ret <= 0) {
        return 0;
    }

    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) {
        return 0;
    }
    fill_header(&seqs, &evt->header, EVT_TLS_ASSOC, sizeof(*evt), ret);
    evt->ssl_ctx = (__u64)ssl;
    evt->fd = fd;
    evt->assoc_ret = ret;
    evt->direction = direction;
    __builtin_memset(&evt->_reserved, 0, sizeof(evt->_reserved));
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

static __always_inline int record_ssl_assoc_args(void *ctx, __u8 direction)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct ssl_assoc_args args = {
        .ssl = (void *)VSK_PARM1(ctx),
        .fd = (__s32)VSK_PARM2(ctx),
        .direction = direction,
    };
    bpf_map_update_elem(&ssl_assoc_args_map, &tid, &args, BPF_ANY);
    return 0;
}

static __always_inline int emit_ssl_assoc_exit(struct pt_regs *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct ssl_assoc_args *args = bpf_map_lookup_elem(&ssl_assoc_args_map, &tid);
    long ret = VSK_RC(ctx);

    if (!args) {
        return 0;
    }
    if (args->direction == 0) {
        emit_tls_assoc(args->ssl, args->fd, (__s32)ret, CONTENT_DIRECTION_READ);
        emit_tls_assoc(args->ssl, args->fd, (__s32)ret, CONTENT_DIRECTION_WRITE);
    } else {
        emit_tls_assoc(args->ssl, args->fd, (__s32)ret, args->direction);
    }
    bpf_map_delete_elem(&ssl_assoc_args_map, &tid);
    return 0;
}

SEC("uprobe")
int handle_ssl_read_enter(struct pt_regs *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct ssl_read_args args = {
        .ssl = (void *)VSK_PARM1(ctx),
        .buf = (void *)VSK_PARM2(ctx),
        .requested = (__u64)VSK_PARM3(ctx),
        .out_len = 0,
    };
    bpf_map_update_elem(&ssl_read_args_map, &tid, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe")
int handle_ssl_read_exit(struct pt_regs *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct ssl_read_args *args = bpf_map_lookup_elem(&ssl_read_args_map, &tid);
    long ret = VSK_RC(ctx);

    if (!args) {
        return 0;
    }
    if (ret > 0) {
        emit_content_frag(args->ssl, args->buf, (__u64)ret, CONTENT_DIRECTION_READ);
    }
    bpf_map_delete_elem(&ssl_read_args_map, &tid);
    return 0;
}

SEC("uprobe")
int handle_ssl_read_ex_enter(struct pt_regs *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct ssl_read_args args = {
        .ssl = (void *)VSK_PARM1(ctx),
        .buf = (void *)VSK_PARM2(ctx),
        .requested = (__u64)VSK_PARM3(ctx),
        .out_len = (void *)(((struct pt_regs_x86_64 *)(ctx))->cx),
    };
    bpf_map_update_elem(&ssl_read_args_map, &tid, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe")
int handle_ssl_read_ex_exit(struct pt_regs *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct ssl_read_args *args = bpf_map_lookup_elem(&ssl_read_args_map, &tid);
    long ret = VSK_RC(ctx);
    __u64 actual = 0;

    if (!args) {
        return 0;
    }
    if (ret == 1 && args->out_len) {
        bpf_probe_read_user(&actual, sizeof(actual), args->out_len);
        if (actual > 0 && actual <= args->requested) {
            emit_content_frag(args->ssl, args->buf, actual, CONTENT_DIRECTION_READ);
        }
    }
    bpf_map_delete_elem(&ssl_read_args_map, &tid);
    return 0;
}

SEC("uprobe")
int handle_ssl_write_enter(struct pt_regs *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct ssl_read_args args = {
        .ssl = (void *)VSK_PARM1(ctx),
        .buf = (void *)VSK_PARM2(ctx),
        .requested = (__u64)VSK_PARM3(ctx),
        .out_len = 0,
    };
    bpf_map_update_elem(&ssl_read_args_map, &tid, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe")
int handle_ssl_write_exit(struct pt_regs *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct ssl_read_args *args = bpf_map_lookup_elem(&ssl_read_args_map, &tid);
    long ret = VSK_RC(ctx);

    if (!args) {
        return 0;
    }
    if (ret > 0 && (__u64)ret <= args->requested) {
        emit_content_frag(args->ssl, args->buf, (__u64)ret, CONTENT_DIRECTION_WRITE);
    }
    bpf_map_delete_elem(&ssl_read_args_map, &tid);
    return 0;
}

SEC("uprobe")
int handle_ssl_write_ex_enter(struct pt_regs *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct ssl_read_args args = {
        .ssl = (void *)VSK_PARM1(ctx),
        .buf = (void *)VSK_PARM2(ctx),
        .requested = (__u64)VSK_PARM3(ctx),
        .out_len = (void *)(((struct pt_regs_x86_64 *)(ctx))->cx),
    };
    bpf_map_update_elem(&ssl_read_args_map, &tid, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe")
int handle_ssl_write_ex_exit(struct pt_regs *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct ssl_read_args *args = bpf_map_lookup_elem(&ssl_read_args_map, &tid);
    long ret = VSK_RC(ctx);
    __u64 actual = 0;

    if (!args) {
        return 0;
    }
    if (ret == 1 && args->out_len) {
        bpf_probe_read_user(&actual, sizeof(actual), args->out_len);
        if (actual > 0 && actual <= args->requested) {
            emit_content_frag(args->ssl, args->buf, actual, CONTENT_DIRECTION_WRITE);
        }
    }
    bpf_map_delete_elem(&ssl_read_args_map, &tid);
    return 0;
}

SEC("uprobe")
int handle_ssl_set_fd_enter(struct pt_regs *ctx)
{
    return record_ssl_assoc_args(ctx, 0);
}

SEC("uretprobe")
int handle_ssl_set_fd_exit(struct pt_regs *ctx)
{
    return emit_ssl_assoc_exit(ctx);
}

SEC("uprobe")
int handle_ssl_set_rfd_enter(struct pt_regs *ctx)
{
    return record_ssl_assoc_args(ctx, CONTENT_DIRECTION_READ);
}

SEC("uretprobe")
int handle_ssl_set_rfd_exit(struct pt_regs *ctx)
{
    return emit_ssl_assoc_exit(ctx);
}

SEC("uprobe")
int handle_ssl_set_wfd_enter(struct pt_regs *ctx)
{
    return record_ssl_assoc_args(ctx, CONTENT_DIRECTION_WRITE);
}

SEC("uretprobe")
int handle_ssl_set_wfd_exit(struct pt_regs *ctx)
{
    return emit_ssl_assoc_exit(ctx);
}

char LICENSE[] SEC("license") = "GPL";
