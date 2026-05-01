#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "common.h"

#define EVT_PROC_FORK 1
#define EVT_PROC_EXEC 2
#define EVT_PROC_EXIT 3
#define EVT_PROC_CHDIR 4
#define EVT_FD_DUP 5
#define PATH_INLINE_MAX 256

struct proc_fork_event {
    struct event_header header;
    __u32 child_pid;
    __u32 child_tid;
    __u32 clone_flags;
    __u32 _pad;
} __attribute__((packed));

struct proc_exec_event {
    struct event_header header;
    __u32 argv_len;
    __u32 filename_len;
    char filename[PATH_INLINE_MAX];
    char argv[PATH_INLINE_MAX];
} __attribute__((packed));

struct proc_exit_event {
    struct event_header header;
    __s32 exit_code;
    __u32 _pad;
} __attribute__((packed));

struct proc_chdir_event {
    struct event_header header;
    __s32 dirfd;
    __u32 _pad;
    __u32 path_len;
    char path[PATH_INLINE_MAX];
} __attribute__((packed));

struct fd_dup_event {
    struct event_header header;
    __s32 oldfd;
    __s32 newfd;
    __s32 dup_ret;
    __u32 _pad;
} __attribute__((packed));

struct sys_enter_args {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    __s32 common_pid;
    long id;
    unsigned long args[6];
};

struct sys_exit_args {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    __s32 common_pid;
    long id;
    long ret;
};

struct sched_process_exec_args {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    __s32 common_pid;
    __u32 __data_loc_filename;
    __u32 pid;
    __u32 old_pid;
};

struct clone_args_state {
    __u64 clone_flags;
};

struct chdir_args_state {
    const char *path;
};

struct fchdir_args_state {
    __s32 fd;
};

struct dup_args_state {
    __s32 oldfd;
    __s32 newfd;
};

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

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, struct clone_args_state);
} clone_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, struct chdir_args_state);
} chdir_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, struct fchdir_args_state);
} fchdir_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, struct dup_args_state);
} dup_args SEC(".maps");

static __always_inline int record_dup_args(__u32 tid, __s32 oldfd, __s32 newfd)
{
    struct dup_args_state args = {
        .oldfd = oldfd,
        .newfd = newfd,
    };
    bpf_map_update_elem(&dup_args, &tid, &args, BPF_ANY);
    return 0;
}

static __always_inline int emit_dup_event(struct sys_exit_args *ctx, __s32 fallback_newfd)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct dup_args_state *args = bpf_map_lookup_elem(&dup_args, &tid);
    struct fd_dup_event *evt;

    if (!args) {
        return 0;
    }
    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) {
        bpf_map_delete_elem(&dup_args, &tid);
        return 0;
    }
    __builtin_memset(evt, 0, sizeof(*evt));
    fill_header(&seqs, &evt->header, EVT_FD_DUP, sizeof(*evt), (__s32)ctx->ret);
    evt->oldfd = args->oldfd;
    /* dup2/dup3 choose the target fd on entry; plain dup reports it as the
     * syscall return value, so keep whichever source is meaningful. */
    evt->newfd = fallback_newfd >= 0 ? fallback_newfd : args->newfd;
    evt->dup_ret = (__s32)ctx->ret;
    bpf_ringbuf_submit(evt, 0);
    bpf_map_delete_elem(&dup_args, &tid);
    return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int handle_sched_process_exec(struct sched_process_exec_args *ctx)
{
    struct proc_exec_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    const char *filename;
    if (!evt) {
        return 0;
    }
    __builtin_memset(evt, 0, sizeof(*evt));
    fill_header(&seqs, &evt->header, EVT_PROC_EXEC, sizeof(*evt), 0);
    /* argv reconstruction is best-effort in user space; the tracepoint gives us
     * the filename reliably without chasing user pointers here. */
    filename = (const char *)ctx + (ctx->__data_loc_filename & 0xFFFF);
    evt->filename_len = bpf_probe_read_kernel_str(&evt->filename, sizeof(evt->filename), filename);
    evt->argv_len = 0;
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int handle_sched_process_exit(void *ctx)
{
    struct proc_exit_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) {
        return 0;
    }
    __builtin_memset(evt, 0, sizeof(*evt));
    fill_header(&seqs, &evt->header, EVT_PROC_EXIT, sizeof(*evt), 0);
    evt->exit_code = 0;
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_clone")
int handle_enter_clone(struct sys_enter_args *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct clone_args_state args = {
        .clone_flags = ctx->args[0],
    };
    bpf_map_update_elem(&clone_args, &tid, &args, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_clone")
int handle_exit_clone(struct sys_exit_args *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct clone_args_state *args = bpf_map_lookup_elem(&clone_args, &tid);
    struct proc_fork_event *evt;
    if (!args || ctx->ret <= 0) {
        bpf_map_delete_elem(&clone_args, &tid);
        return 0;
    }
    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) {
        bpf_map_delete_elem(&clone_args, &tid);
        return 0;
    }
    __builtin_memset(evt, 0, sizeof(*evt));
    fill_header(&seqs, &evt->header, EVT_PROC_FORK, sizeof(*evt), (__s32)ctx->ret);
    evt->child_pid = (__u32)ctx->ret;
    evt->child_tid = (__u32)ctx->ret;
    evt->clone_flags = args->clone_flags;
    bpf_ringbuf_submit(evt, 0);
    bpf_map_delete_elem(&clone_args, &tid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_chdir")
int handle_enter_chdir(struct sys_enter_args *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct chdir_args_state args = {
        .path = (const char *)ctx->args[0],
    };
    bpf_map_update_elem(&chdir_args, &tid, &args, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_chdir")
int handle_exit_chdir(struct sys_exit_args *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct chdir_args_state *args = bpf_map_lookup_elem(&chdir_args, &tid);
    struct proc_chdir_event *evt;
    if (!args) {
        return 0;
    }
    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) {
        bpf_map_delete_elem(&chdir_args, &tid);
        return 0;
    }
    __builtin_memset(evt, 0, sizeof(*evt));
    fill_header(&seqs, &evt->header, EVT_PROC_CHDIR, sizeof(*evt), (__s32)ctx->ret);
    evt->dirfd = -100;
    evt->path_len = bpf_probe_read_user_str(&evt->path, sizeof(evt->path), args->path);
    bpf_ringbuf_submit(evt, 0);
    bpf_map_delete_elem(&chdir_args, &tid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchdir")
int handle_enter_fchdir(struct sys_enter_args *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct fchdir_args_state args = {
        .fd = (__s32)ctx->args[0],
    };
    bpf_map_update_elem(&fchdir_args, &tid, &args, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fchdir")
int handle_exit_fchdir(struct sys_exit_args *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct fchdir_args_state *args = bpf_map_lookup_elem(&fchdir_args, &tid);
    struct proc_chdir_event *evt;
    if (!args) {
        return 0;
    }
    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) {
        bpf_map_delete_elem(&fchdir_args, &tid);
        return 0;
    }
    __builtin_memset(evt, 0, sizeof(*evt));
    fill_header(&seqs, &evt->header, EVT_PROC_CHDIR, sizeof(*evt), (__s32)ctx->ret);
    evt->dirfd = args->fd;
    evt->path_len = 0;
    bpf_ringbuf_submit(evt, 0);
    bpf_map_delete_elem(&fchdir_args, &tid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_dup")
int handle_enter_dup(struct sys_enter_args *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    return record_dup_args(tid, (__s32)ctx->args[0], -1);
}

SEC("tracepoint/syscalls/sys_exit_dup")
int handle_exit_dup(struct sys_exit_args *ctx)
{
    return emit_dup_event(ctx, (__s32)ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_dup2")
int handle_enter_dup2(struct sys_enter_args *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    return record_dup_args(tid, (__s32)ctx->args[0], (__s32)ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_exit_dup2")
int handle_exit_dup2(struct sys_exit_args *ctx)
{
    return emit_dup_event(ctx, -1);
}

SEC("tracepoint/syscalls/sys_enter_dup3")
int handle_enter_dup3(struct sys_enter_args *ctx)
{
    return handle_enter_dup2(ctx);
}

SEC("tracepoint/syscalls/sys_exit_dup3")
int handle_exit_dup3(struct sys_exit_args *ctx)
{
    return emit_dup_event(ctx, -1);
}

SEC("tracepoint/syscalls/sys_enter_close")
int handle_enter_close(struct sys_enter_args *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    return record_dup_args(tid, -1, (__s32)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_exit_close")
int handle_exit_close(struct sys_exit_args *ctx)
{
    return emit_dup_event(ctx, -1);
}

char LICENSE[] SEC("license") = "GPL";
