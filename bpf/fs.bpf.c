#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "common.h"

#define EVT_FILE_OPEN 10
#define EVT_FILE_UNLINK 11
#define EVT_FILE_RENAME 12

struct file_open_event {
    struct event_header header;
    __s32 dirfd;
    __s32 ret_fd;
    __u32 flags;
    __u32 mode;
    __u64 inode;
    __u64 dev;
    __u32 path_len;
    char path[PATH_INLINE_MAX];
} __attribute__((packed));

struct file_unlink_event {
    struct event_header header;
    __s32 dirfd;
    __s32 unlink_ret;
    __u32 flags;
    __u32 path_len;
    char path[PATH_INLINE_MAX];
} __attribute__((packed));

struct file_rename_event {
    struct event_header header;
    __s32 olddirfd;
    __s32 newdirfd;
    __s32 rename_ret;
    __u32 flags;
    __u32 oldpath_len;
    __u32 newpath_len;
    char paths[PATH_INLINE_MAX * 2];
} __attribute__((packed));

struct open_how_local {
    __u64 flags;
    __u64 mode;
    __u64 resolve;
};

struct open_args_state {
    __s32 dirfd;
    const char *path;
    __u32 flags;
    __u32 mode;
};

struct unlink_args_state {
    __s32 dirfd;
    const char *path;
    __u32 flags;
};

struct rename_args_state {
    __s32 olddirfd;
    __s32 newdirfd;
    const char *oldpath;
    const char *newpath;
    __u32 flags;
};

VERISKEIN_EVENT_MAPS

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, PENDING_ARGS_MAX_ENTRIES);
    __type(key, __u32);
    __type(value, struct open_args_state);
} open_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, PENDING_ARGS_MAX_ENTRIES);
    __type(key, __u32);
    __type(value, struct unlink_args_state);
} unlink_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, PENDING_ARGS_MAX_ENTRIES);
    __type(key, __u32);
    __type(value, struct rename_args_state);
} rename_args SEC(".maps");

static __always_inline int record_open_args(struct sys_enter_args *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct open_args_state args = {
        .dirfd = (__s32)ctx->args[0],
        .path = (const char *)ctx->args[1],
        .flags = (__u32)ctx->args[2],
        .mode = (__u32)ctx->args[3],
    };
    bpf_map_update_elem(&open_args, &tid, &args, BPF_ANY);
    return 0;
}

static __always_inline int record_openat2_args(struct sys_enter_args *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct open_how_local how = {};
    bpf_probe_read_user(&how, sizeof(how), (const void *)ctx->args[2]);
    struct open_args_state args = {
        .dirfd = (__s32)ctx->args[0],
        .path = (const char *)ctx->args[1],
        .flags = (__u32)how.flags,
        .mode = (__u32)how.mode,
    };
    bpf_map_update_elem(&open_args, &tid, &args, BPF_ANY);
    return 0;
}

static __always_inline int emit_open_event(struct sys_exit_args *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct open_args_state *args = bpf_map_lookup_elem(&open_args, &tid);
    struct file_open_event *evt;

    if (!args) {
        return 0;
    }
    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) {
        bpf_map_delete_elem(&open_args, &tid);
        return 0;
    }
    __builtin_memset(evt, 0, sizeof(*evt));
    fill_header(&seqs, &evt->header, EVT_FILE_OPEN, sizeof(*evt), (__s32)ctx->ret);
    evt->dirfd = args->dirfd;
    evt->ret_fd = (__s32)ctx->ret;
    evt->flags = args->flags;
    evt->mode = args->mode;
    /* The raw syscall path is captured before any user-space canonicalization so
     * the normalizer can decide when lexical vs canonical resolution matters. */
    evt->path_len = bpf_probe_read_user_str(&evt->path, sizeof(evt->path), args->path);
    bpf_ringbuf_submit(evt, 0);
    bpf_map_delete_elem(&open_args, &tid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_enter_openat(struct sys_enter_args *ctx)
{
    return record_open_args(ctx);
}

SEC("tracepoint/syscalls/sys_exit_openat")
int handle_exit_openat(struct sys_exit_args *ctx)
{
    return emit_open_event(ctx);
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int handle_enter_openat2(struct sys_enter_args *ctx)
{
    return record_openat2_args(ctx);
}

SEC("tracepoint/syscalls/sys_exit_openat2")
int handle_exit_openat2(struct sys_exit_args *ctx)
{
    return emit_open_event(ctx);
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int handle_enter_unlinkat(struct sys_enter_args *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct unlink_args_state args = {
        .dirfd = (__s32)ctx->args[0],
        .path = (const char *)ctx->args[1],
        .flags = (__u32)ctx->args[2],
    };
    bpf_map_update_elem(&unlink_args, &tid, &args, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_unlinkat")
int handle_exit_unlinkat(struct sys_exit_args *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct unlink_args_state *args = bpf_map_lookup_elem(&unlink_args, &tid);
    struct file_unlink_event *evt;
    if (!args) {
        return 0;
    }
    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) {
        bpf_map_delete_elem(&unlink_args, &tid);
        return 0;
    }
    __builtin_memset(evt, 0, sizeof(*evt));
    fill_header(&seqs, &evt->header, EVT_FILE_UNLINK, sizeof(*evt), (__s32)ctx->ret);
    evt->dirfd = args->dirfd;
    evt->unlink_ret = (__s32)ctx->ret;
    evt->flags = args->flags;
    evt->path_len = bpf_probe_read_user_str(&evt->path, sizeof(evt->path), args->path);
    bpf_ringbuf_submit(evt, 0);
    bpf_map_delete_elem(&unlink_args, &tid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_renameat2")
int handle_enter_renameat2(struct sys_enter_args *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct rename_args_state args = {
        .olddirfd = (__s32)ctx->args[0],
        .oldpath = (const char *)ctx->args[1],
        .newdirfd = (__s32)ctx->args[2],
        .newpath = (const char *)ctx->args[3],
        .flags = (__u32)ctx->args[4],
    };
    bpf_map_update_elem(&rename_args, &tid, &args, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_renameat2")
int handle_exit_renameat2(struct sys_exit_args *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct rename_args_state *args = bpf_map_lookup_elem(&rename_args, &tid);
    struct file_rename_event *evt;
    int old_len;
    if (!args) {
        return 0;
    }
    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) {
        bpf_map_delete_elem(&rename_args, &tid);
        return 0;
    }
    __builtin_memset(evt, 0, sizeof(*evt));
    fill_header(&seqs, &evt->header, EVT_FILE_RENAME, sizeof(*evt), (__s32)ctx->ret);
    evt->olddirfd = args->olddirfd;
    evt->newdirfd = args->newdirfd;
    evt->rename_ret = (__s32)ctx->ret;
    evt->flags = args->flags;
    old_len = bpf_probe_read_user_str(&evt->paths, PATH_INLINE_MAX, args->oldpath);
    if (old_len < 0) {
        old_len = 0;
    }
    evt->oldpath_len = old_len;
    /* Old and new paths live in one inline buffer to keep the wire format fixed
     * width for ring buffer emission and plain parsing. */
    evt->newpath_len = bpf_probe_read_user_str(&evt->paths[PATH_INLINE_MAX], PATH_INLINE_MAX, args->newpath);
    bpf_ringbuf_submit(evt, 0);
    bpf_map_delete_elem(&rename_args, &tid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
