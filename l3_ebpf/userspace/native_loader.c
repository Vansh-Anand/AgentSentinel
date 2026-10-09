#include <stdio.h>
#include <stdlib.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <sys/resource.h>
#include <stddef.h>
#include "../kernel/events.h"

// Python callback signature
typedef void (*event_cb)(const struct syscall_event_t *event, int size);

// Define a handle structure to hold our objects
struct native_ebpf_handle {
    struct bpf_object *obj;
    struct bpf_link *links[3];
    struct ring_buffer *rb;
    event_cb callback;
};

int native_event_size(void) {
    return (int)sizeof(struct syscall_event_t);
}

int native_event_offset(int field) {
    static const int offsets[] = {
        offsetof(struct syscall_event_t, type),
        offsetof(struct syscall_event_t, timestamp_ns),
        offsetof(struct syscall_event_t, cgroup_id),
        offsetof(struct syscall_event_t, executable),
        offsetof(struct syscall_event_t, address),
        offsetof(struct syscall_event_t, open_flags),
        offsetof(struct syscall_event_t, dirfd),
        offsetof(struct syscall_event_t, address_valid)
    };
    return field >= 0 && field < 8 ? offsets[field] : -1;
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    struct native_ebpf_handle *h = ctx;
    if (h && h->callback) {
        h->callback((const struct syscall_event_t *)data, (int)data_sz);
    }
    return 0;
}

// Exported C function to initialize and load the BPF program
struct native_ebpf_handle *init_bpf(const char *obj_file) {
    struct native_ebpf_handle *h = calloc(1, sizeof(*h));
    if (!h) return NULL;

    h->obj = NULL;
    h->rb = NULL;

    // Bump RLIMIT_MEMLOCK to allow BPF map creation
    struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
    setrlimit(RLIMIT_MEMLOCK, &rlim);

    h->obj = bpf_object__open_file(obj_file, NULL);
    if (libbpf_get_error(h->obj)) {
        fprintf(stderr, "ERROR: opening BPF object file failed\n");
        free(h);
        return NULL;
    }

    if (bpf_object__load(h->obj)) {
        fprintf(stderr, "ERROR: loading BPF object file failed\n");
        bpf_object__close(h->obj);
        free(h);
        return NULL;
    }

    const char *programs[] = {
        "tracepoint__syscalls__sys_enter_execve",
        "tracepoint__syscalls__sys_enter_openat",
        "tracepoint__syscalls__sys_enter_connect"
    };
    for (int i = 0; i < 3; i++) {
        struct bpf_program *prog = bpf_object__find_program_by_name(h->obj, programs[i]);
        if (!prog) {
            fprintf(stderr, "ERROR: missing BPF program %s\n", programs[i]);
            goto attach_failed;
        }
        h->links[i] = bpf_program__attach(prog);
        if (libbpf_get_error(h->links[i])) {
            h->links[i] = NULL;
            fprintf(stderr, "ERROR: attaching BPF program %s failed\n", programs[i]);
            goto attach_failed;
        }
    }

    return h;
attach_failed:
    for (int i = 0; i < 3; i++) {
        if (h->links[i]) bpf_link__destroy(h->links[i]);
    }
    bpf_object__close(h->obj);
    free(h);
    return NULL;
}

// Exported C function to start the ring buffer
int start_ringbuffer(struct native_ebpf_handle *h, event_cb callback) {
    if (!h || !h->obj) return -1;
    h->callback = callback;

    int map_fd = bpf_object__find_map_fd_by_name(h->obj, "rb");
    if (map_fd < 0) {
        fprintf(stderr, "ERROR: finding a map in obj file failed\n");
        return -1;
    }

    h->rb = ring_buffer__new(map_fd, handle_event, h, NULL);
    if (!h->rb) {
        fprintf(stderr, "ERROR: creating ring buffer failed\n");
        return -1;
    }
    return 0;
}

// Exported C function to poll the ring buffer
int poll_ringbuffer(struct native_ebpf_handle *h, int timeout_ms) {
    if (!h || !h->rb) return -1;
    return ring_buffer__poll(h->rb, timeout_ms);
}

int update_cgroup_filter(struct native_ebpf_handle *h, unsigned long long cgroup_id, int enabled) {
    if (!h || !h->obj || !cgroup_id) return -1;
    int fd = bpf_object__find_map_fd_by_name(h->obj, "cgroup_filter");
    if (fd < 0) return -1;
    if (!enabled) return bpf_map_delete_elem(fd, &cgroup_id);
    unsigned char value = 1;
    return bpf_map_update_elem(fd, &cgroup_id, &value, BPF_ANY);
}

long long read_dropped_events(struct native_ebpf_handle *h) {
    if (!h || !h->obj) return -1;
    int fd = bpf_object__find_map_fd_by_name(h->obj, "dropped_events");
    if (fd < 0) return -1;
    unsigned int zero = 0;
    unsigned long long value = 0;
    if (bpf_map_lookup_elem(fd, &zero, &value)) return -1;
    return (long long)value;
}

// Exported C function to cleanup
void cleanup_bpf(struct native_ebpf_handle *h) {
    if (!h) return;
    if (h->rb) ring_buffer__free(h->rb);
    for (int i = 0; i < 3; i++) {
        if (h->links[i]) bpf_link__destroy(h->links[i]);
    }
    if (h->obj) bpf_object__close(h->obj);
    free(h);
}
