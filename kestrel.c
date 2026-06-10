//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define MAX_QUERY_LEN 256
#define PG_PORT 5433

char LICENSE[] SEC("license") = "GPL";

struct query_event {
    __u32 pid;
    __u32 _pad; // padding
    __u64 ts;
    char  comm[16];
    char  query[MAX_QUERY_LEN];
} __attribute__((packed));

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

    // On kernel 5.20+, single-buffer sends use ITER_UBUF (iter_type=0)
    // Data pointer lives directly in msg_iter.ubuf — one level, verifier safe
    __u8 iter_type = BPF_CORE_READ(msg, msg_iter.iter_type);
    __u64 uaddr = 0;

    if (iter_type == 0) {
        uaddr = (__u64)(unsigned long)BPF_CORE_READ(msg, msg_iter.ubuf);
    } else {
        // fallback: ITER_IOVEC — read base from first iovec via kernel read
        const struct iovec *iov = BPF_CORE_READ(msg, msg_iter.__iov);
        if (!iov) return 0;
        __u64 base = 0;
        bpf_probe_read_kernel(&base, sizeof(base), &iov->iov_base);
        uaddr = base;
    }

    if (!uaddr)
        return 0;

    // Check Postgres simple query protocol — first byte must be 'Q'
    __u8 msg_type = 0;
    bpf_probe_read_user(&msg_type, sizeof(msg_type), (void *)uaddr);
    if (msg_type != 'Q')
        return 0;

    struct query_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->ts  = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    __builtin_memset(e->query, 0, sizeof(e->query));

    // Skip 5 bytes: 1 type byte + 4 length bytes
    bpf_probe_read_user(e->query, sizeof(e->query) - 1, (void *)(uaddr + 5));

    bpf_ringbuf_submit(e, 0);
    return 0;
}