#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "common.h"

#define EVT_NET_CONNECT 20

struct net_connect_event {
    struct event_header header;
    __s32 sockfd;
    __s32 connect_ret;
    __u16 family;
    __u16 dport_be;
    __u16 sport_be;
    __u8 tls_candidate;
    __u8 _pad0;
    __u8 _pad1;
    __u8 addr_dst[16];
    __u8 addr_src[16];
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

struct sockaddr_in_raw {
    __u16 family;
    __u16 port_be;
    __u32 addr_be;
    __u8 pad[8];
};

struct sockaddr_in6_raw {
    __u16 family;
    __u16 port_be;
    __u32 flowinfo;
    __u8 addr[16];
    __u32 scope_id;
};

struct connect_args_state {
    __s32 sockfd;
    const void *addr;
    __s32 addrlen;
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
    __type(value, struct connect_args_state);
} connect_args SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_connect")
int handle_enter_connect(struct sys_enter_args *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct connect_args_state args = {
        .sockfd = (__s32)ctx->args[0],
        .addr = (const void *)ctx->args[1],
        .addrlen = (__s32)ctx->args[2],
    };
    bpf_map_update_elem(&connect_args, &tid, &args, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int handle_exit_connect(struct sys_exit_args *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct connect_args_state *args = bpf_map_lookup_elem(&connect_args, &tid);
    struct net_connect_event *evt;
    __u16 family = 0;
    if (!args) {
        return 0;
    }
    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) {
        bpf_map_delete_elem(&connect_args, &tid);
        return 0;
    }
    __builtin_memset(evt, 0, sizeof(*evt));
    fill_header(&seqs, &evt->header, EVT_NET_CONNECT, sizeof(*evt), (__s32)ctx->ret);
    evt->sockfd = args->sockfd;
    evt->connect_ret = (__s32)ctx->ret;
    bpf_probe_read_user(&family, sizeof(family), args->addr);
    evt->family = family;
    if (family == 2) {
        struct sockaddr_in_raw sin = {};
        bpf_probe_read_user(&sin, sizeof(sin), args->addr);
        evt->dport_be = sin.port_be;
        __builtin_memcpy(&evt->addr_dst[12], &sin.addr_be, sizeof(sin.addr_be));
    } else if (family == 10) {
        struct sockaddr_in6_raw sin6 = {};
        bpf_probe_read_user(&sin6, sizeof(sin6), args->addr);
        evt->dport_be = sin6.port_be;
        __builtin_memcpy(&evt->addr_dst, &sin6.addr, sizeof(sin6.addr));
    }
    evt->tls_candidate = evt->dport_be == __builtin_bswap16(443);
    bpf_ringbuf_submit(evt, 0);
    bpf_map_delete_elem(&connect_args, &tid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
