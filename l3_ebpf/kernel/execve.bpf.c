#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "events.h"

// Ring buffer for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB
} rb SEC(".maps");

// Map to filter allowed cgroups
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64); // cgroup_id
    __type(value, u8); // allowed flag
} cgroup_filter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} dropped_events SEC(".maps");

static __always_inline struct syscall_event_t *reserve_event(unsigned int event_type)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tid = (u32)id;
    
    u64 cgroup_id = bpf_get_current_cgroup_id();
    
    // Check if this cgroup is monitored
    u8 *monitored = bpf_map_lookup_elem(&cgroup_filter, &cgroup_id);
    if (!monitored) {
        return 0;
    }

    struct syscall_event_t *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        u32 zero = 0;
        u64 *count = bpf_map_lookup_elem(&dropped_events, &zero);
        if (count) __sync_fetch_and_add(count, 1);
        return 0;
    }

    __builtin_memset(e, 0, sizeof(*e));

    e->type = event_type;
    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid = pid;
    e->tid = tid;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    e->cgroup_id = cgroup_id;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->gid = bpf_get_current_uid_gid() >> 32;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    // All probes observe syscall entry only; no successful outcome is implied.
    e->ret = -1;

    return e;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event_t *e = reserve_event(EVENT_EXECVE);
    if (!e) return 0;
    bpf_probe_read_user_str(e->executable, sizeof(e->executable),
                            (const char *)ctx->args[0]);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event_t *e = reserve_event(EVENT_OPENAT);
    if (!e) return 0;
    e->dirfd = (int)ctx->args[0];
    e->open_flags = (unsigned int)ctx->args[2];
    bpf_probe_read_user_str(e->executable, sizeof(e->executable),
                            (const char *)ctx->args[1]);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

struct ipv4_sockaddr {
    unsigned short family;
    unsigned short port;
    unsigned int address;
};

struct ipv6_sockaddr {
    unsigned short family;
    unsigned short port;
    unsigned int flowinfo;
    unsigned char address[16];
};

SEC("tracepoint/syscalls/sys_enter_connect")
int tracepoint__syscalls__sys_enter_connect(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event_t *e = reserve_event(EVENT_CONNECT);
    if (!e) return 0;
    unsigned short family = 0;
    const void *address = (const void *)ctx->args[1];
    if (bpf_probe_read_user(&family, sizeof(family), address) == 0) {
        e->addr_family = family;
        if (family == 2 && ctx->args[2] >= sizeof(struct ipv4_sockaddr)) {
            struct ipv4_sockaddr peer = {};
            if (bpf_probe_read_user(&peer, sizeof(peer), address) == 0) {
                e->port_be = peer.port;
                __builtin_memcpy(e->address, &peer.address, 4);
                e->address_valid = 1;
            }
        } else if (family == 10 && ctx->args[2] >= sizeof(struct ipv6_sockaddr)) {
            struct ipv6_sockaddr peer = {};
            if (bpf_probe_read_user(&peer, sizeof(peer), address) == 0) {
                e->port_be = peer.port;
                __builtin_memcpy(e->address, peer.address, 16);
                e->address_valid = 1;
            }
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
