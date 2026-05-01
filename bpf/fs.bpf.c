#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define EVT_ABI_VERSION 1
#define EVT_FILE_OPEN 10
#define EVT_FILE_UNLINK 11
#define EVT_FILE_RENAME 12
#define TASK_COMM_LEN 16
#define PATH_INLINE_MAX 256

struct event_header {
    __u64 ts_ns;
    __u32 abi_version;
    __u16 kind;
    __u16 total_len;
    __u32 pid;
    __u32 tid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    __u64 cgroup_id;
    __u32 cpu;
    __u64 seq;
    __u64 mount_ns;
    __s32 ret;
    __u32 _reserved;
    char comm[TASK_COMM_LEN];
} __attribute__((packed));

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
    __type(value, struct open_args_state);
} open_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, struct unlink_args_state);
} unlink_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, struct rename_args_state);
} rename_args SEC(".maps");

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

static __always_inline void fill_header(struct event_header *hdr, __u16 kind, __u16 total_len, __s32 ret)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();
    __builtin_memset(hdr, 0, sizeof(*hdr));
    hdr->ts_ns = bpf_ktime_get_ns();
    hdr->abi_version = EVT_ABI_VERSION;
    hdr->kind = kind;
    hdr->total_len = total_len;
    hdr->pid = (__u32)(pid_tgid >> 32);
    hdr->tid = (__u32)pid_tgid;
    hdr->uid = (__u32)uid_gid;
    hdr->gid = (__u32)(uid_gid >> 32);
    hdr->cgroup_id = bpf_get_current_cgroup_id();
    hdr->cpu = bpf_get_smp_processor_id();
    hdr->seq = next_seq();
    hdr->ret = ret;
    bpf_get_current_comm(&hdr->comm, sizeof(hdr->comm));
}

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_enter_openat(struct sys_enter_args *ctx)
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

SEC("tracepoint/syscalls/sys_exit_openat")
int handle_exit_openat(struct sys_exit_args *ctx)
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
    fill_header(&evt->header, EVT_FILE_OPEN, sizeof(*evt), (__s32)ctx->ret);
    evt->dirfd = args->dirfd;
    evt->ret_fd = (__s32)ctx->ret;
    evt->flags = args->flags;
    evt->mode = args->mode;
    evt->path_len = bpf_probe_read_user_str(&evt->path, sizeof(evt->path), args->path);
    bpf_ringbuf_submit(evt, 0);
    bpf_map_delete_elem(&open_args, &tid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int handle_enter_openat2(struct sys_enter_args *ctx)
{
    return handle_enter_openat(ctx);
}

SEC("tracepoint/syscalls/sys_exit_openat2")
int handle_exit_openat2(struct sys_exit_args *ctx)
{
    return handle_exit_openat(ctx);
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
    fill_header(&evt->header, EVT_FILE_UNLINK, sizeof(*evt), (__s32)ctx->ret);
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
    fill_header(&evt->header, EVT_FILE_RENAME, sizeof(*evt), (__s32)ctx->ret);
    evt->olddirfd = args->olddirfd;
    evt->newdirfd = args->newdirfd;
    evt->rename_ret = (__s32)ctx->ret;
    evt->flags = args->flags;
    old_len = bpf_probe_read_user_str(&evt->paths, PATH_INLINE_MAX, args->oldpath);
    if (old_len < 0) {
        old_len = 0;
    }
    evt->oldpath_len = old_len;
    evt->newpath_len = bpf_probe_read_user_str(&evt->paths[PATH_INLINE_MAX], PATH_INLINE_MAX, args->newpath);
    bpf_ringbuf_submit(evt, 0);
    bpf_map_delete_elem(&rename_args, &tid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
