#ifndef __ACADEMIQ_EVENTS_H
#define __ACADEMIQ_EVENTS_H

#define TASK_COMM_LEN 16
#define MAX_ARGS 16
#define MAX_ARG_LEN 64
#define MAX_FILENAME_LEN 256

/* Event types */
enum event_type {
    EVENT_EXECVE = 1,
    EVENT_OPENAT = 2,
    EVENT_CONNECT = 3
};

struct syscall_event_t {
    unsigned int type;
    unsigned long long timestamp_ns;
    
    /* Identity */
    unsigned int pid;
    unsigned int tid;
    unsigned int ppid;
    unsigned int uid;
    unsigned int gid;
    unsigned long long cgroup_id;
    
    char comm[TASK_COMM_LEN];
    char executable[MAX_FILENAME_LEN];
    
    /* Syscall specific */
    int ret;
    
    /* Payload / args string */
    char arg_payload[256];

    /* Added without changing the prefix consumed by earlier collectors. */
    unsigned short addr_family;
    unsigned short port_be;
    unsigned char address[16];
    unsigned int open_flags;
    int dirfd;
    unsigned char address_valid;
};

#endif /* __ACADEMIQ_EVENTS_H */
