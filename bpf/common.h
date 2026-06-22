#ifndef VERISKEIN_COMMON_H
#define VERISKEIN_COMMON_H

#include "vmlinux.h"
#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#define EVT_ABI_VERSION 2
#define TASK_COMM_LEN 16

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

#define VERISKEIN_EVENT_MAPS                                                   \
    struct {                                                                   \
        __uint(type, BPF_MAP_TYPE_RINGBUF);                                    \
        __uint(max_entries, 16 * 1024 * 1024);                                 \
    } events SEC(".maps");                                                    \
                                                                               \
    struct {                                                                   \
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);                               \
        __uint(max_entries, 1);                                                \
        __type(key, __u32);                                                    \
        __type(value, __u64);                                                  \
    } seqs SEC(".maps");

struct task_struct___local {
    struct task_struct___local *real_parent;
    __u32 tgid;
    struct nsproxy___local *nsproxy;
};

struct nsproxy___local {
    struct mnt_namespace___local *mnt_ns;
};

struct mnt_namespace___local {
    struct {
        __u32 inum;
    } ns;
};

static __always_inline __u64 next_seq(void *seqs)
{
    __u32 key = 0;
    __u64 init = 0;
    /* One per-CPU counter is enough here because user space tracks gaps and
     * ordering independently for each CPU stream. */
    __u64 *seq = bpf_map_lookup_elem(seqs, &key);
    if (!seq) {
        bpf_map_update_elem(seqs, &key, &init, BPF_ANY);
        seq = bpf_map_lookup_elem(seqs, &key);
        if (!seq) {
            return 0;
        }
    }
    *seq += 1;
    return *seq;
}

static __always_inline __u32 current_ppid(void *task)
{
    struct task_struct___local *parent =
        BPF_CORE_READ((struct task_struct___local *)task, real_parent);
    if (!parent) {
        return 0;
    }
    return BPF_CORE_READ(parent, tgid);
}

static __always_inline __u64 current_mount_ns(void *task)
{
    struct nsproxy___local *nsproxy =
        BPF_CORE_READ((struct task_struct___local *)task, nsproxy);
    struct mnt_namespace___local *mnt_ns;

    if (!nsproxy) {
        return 0;
    }

    mnt_ns = BPF_CORE_READ(nsproxy, mnt_ns);
    if (!mnt_ns) {
        return 0;
    }

    return BPF_CORE_READ(mnt_ns, ns.inum);
}

static __always_inline void fill_header(void *seqs, struct event_header *hdr, __u16 kind, __u16 total_len, __s32 ret)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();
    void *task = (void *)bpf_get_current_task_btf();

    __builtin_memset(hdr, 0, sizeof(*hdr));
    /* Every emitted payload shares this header contract with veriskein-proto. */
    hdr->ts_ns = bpf_ktime_get_ns();
    hdr->abi_version = EVT_ABI_VERSION;
    hdr->kind = kind;
    hdr->total_len = total_len;
    hdr->pid = (__u32)(pid_tgid >> 32);
    hdr->tid = (__u32)pid_tgid;
    hdr->ppid = task ? current_ppid(task) : 0;
    hdr->uid = (__u32)uid_gid;
    hdr->gid = (__u32)(uid_gid >> 32);
    hdr->cgroup_id = bpf_get_current_cgroup_id();
    hdr->cpu = bpf_get_smp_processor_id();
    hdr->seq = next_seq(seqs);
    hdr->mount_ns = task ? current_mount_ns(task) : 0;
    hdr->ret = ret;
    bpf_get_current_comm(&hdr->comm, sizeof(hdr->comm));
}

#endif
