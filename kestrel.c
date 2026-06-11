//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define MAX_QUERY_LEN 256
#define PG_PORT 5433

char LICENSE[] SEC("license") = "GPL";

// In-flight query stored in hashmap
struct query_start {
    __u64 ts;
    __u32 pid;
    __u32 _pad;
    char  comm[16];
    char  query[MAX_QUERY_LEN];
};

// Completed query emitted to userspace
struct query_event {
    __u32 pid;
    __u32 _pad;
    __u64 ts;
    __u64 duration_ns;
    char  comm[16];
    char  query[MAX_QUERY_LEN];
} __attribute__((packed));

// Hashmap: sock pointer → in-flight query
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct query_start);
} query_starts SEC(".maps");

// Ring buffer: completed events → userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(kestrel_tcp_sendmsg, struct sock *sk,
               struct msghdr *msg, size_t size)
{
    __u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    if (bpf_ntohs(dport) != PG_PORT)
        return 0;

    if (size < 5)
        return 0;

    __u8 iter_type = BPF_CORE_READ(msg, msg_iter.iter_type);
    __u64 uaddr = 0;

    if (iter_type == 0) {
        uaddr = (__u64)(unsigned long)BPF_CORE_READ(msg, msg_iter.ubuf);
    } else {
        const struct iovec *iov = BPF_CORE_READ(msg, msg_iter.__iov);
        if (!iov) return 0;
        __u64 base = 0;
        bpf_probe_read_kernel(&base, sizeof(base), &iov->iov_base);
        uaddr = base;
    }

    if (!uaddr) return 0;

    __u8 msg_type = 0;
    bpf_probe_read_user(&msg_type, sizeof(msg_type), (void *)uaddr);
    if (msg_type != 'Q')
        return 0;

    // Key: sock pointer — unique per TCP connection
    __u64 key = (__u64)(unsigned long)sk;

    struct query_start qs = {};
    qs.ts  = bpf_ktime_get_ns();
    qs.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&qs.comm, sizeof(qs.comm));
    bpf_probe_read_user(qs.query, sizeof(qs.query) - 1, (void *)(uaddr + 5));

    bpf_map_update_elem(&query_starts, &key, &qs, BPF_ANY);
    return 0;
}

SEC("kprobe/tcp_recvmsg")
int BPF_KPROBE(kestrel_tcp_recvmsg, struct sock *sk)
{
    __u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    if (bpf_ntohs(dport) != PG_PORT)
        return 0;

    __u64 key = (__u64)(unsigned long)sk;

    struct query_start *qs = bpf_map_lookup_elem(&query_starts, &key);
    if (!qs) return 0;

    __u64 duration = bpf_ktime_get_ns() - qs->ts;

    struct query_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bpf_map_delete_elem(&query_starts, &key);
        return 0;
    }

    e->pid         = qs->pid;
    e->_pad        = 0;
    e->ts          = qs->ts;
    e->duration_ns = duration;
    __builtin_memcpy(e->comm,  qs->comm,  sizeof(e->comm));
    __builtin_memcpy(e->query, qs->query, sizeof(e->query));

    bpf_ringbuf_submit(e, 0);
    bpf_map_delete_elem(&query_starts, &key);
    return 0;
}