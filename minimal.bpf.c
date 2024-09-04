#include <stdint.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "common.h"
#include <linux/ptrace.h>
#include <linux/in.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/tcp.h>

#define MAX_IOVEC 16

char LICENSE[] SEC("license") = "Dual BSD/GPL";

int my_pid = 0;
int my_fd = -1;  // Track the file descriptor for "test.txt"

//ring buffer map
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024); //1MB
} events SEC(".maps");

//hashmap to track file descriptor
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, int);
} fd_map SEC(".maps");

//string comparison checker function
static __always_inline int str_equals(const char *str1, const char *str2) {
    int i;
    #pragma unroll
    for (i = 0; i < 128; i++) {
        if (str1[i] == '\0' && str2[i] == '\0') {
            return 1;
        }
        if (str1[i] != str2[i]) {
            return 0;
        }
    }
    return 0;
}


int dummy = 0;

// Handle file open events
SEC("tracepoint/syscalls/sys_enter_openat")
int handle_open(struct trace_event_raw_sys_enter_openat *ctx) {
    int pid = bpf_get_current_pid_tgid() >> 32;
    //bpf_printk("enter open triggered\n");
    if (pid != my_pid) return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bpf_printk("bpf_ringbuf_reserve failed");
        return 0;
    }

    char fname[128];

    //copying over data to local variable
    bpf_probe_read_str(fname, sizeof(fname), ctx->filename);
        int fd = 0;
        dummy++;
        bpf_map_update_elem(&fd_map, &dummy, &fd, BPF_ANY); //if filename is test.txt, then update hash map with dummy var
        bpf_printk("dummy:%d Opening file: %s", dummy, fname);

        //rb setup and submission
        e->event_type = EVENT_OPENTER;
        e->fd = -1; //placeholder for the exit handler which will change when the exit openat is called
        bpf_probe_read_str(e->filename, sizeof(e->filename), fname);
        bpf_ringbuf_submit(e, 0);

    return 0;
}

// Handle file open exit events
SEC("tracepoint/syscalls/sys_exit_openat")
int handle_open_exit(struct trace_event_raw_sys_exit_int64 *ctx) {
    int pid = bpf_get_current_pid_tgid() >> 32;
    //bpf_printk("enter exit triggered\n");

    if (pid != my_pid || my_fd != -1) return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bpf_printk("bpf_ringbuf_reserve failed");
        return 0;
    }

    //
    int *fd_ptr = bpf_map_lookup_elem(&fd_map, &dummy); //find the dummy index inside the hashmap
    if (fd_ptr) {
        *fd_ptr = ctx->ret; //save the fd for test.txt    
        my_fd = ctx->ret;

        //rb setup and submission
        e->event_type = EVENT_OPEN;
        e->fd = my_fd;
        bpf_printk("dummy: %d File descriptor for test.txt: %d", dummy, ctx->ret);
        bpf_ringbuf_submit(e, 0);
    } else {
        bpf_printk("Hashmap entry not found\n");
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    // Submit the event
    //bpf_ringbuf_submit(e, 0);

    return 0;
}
// Handle write events to the tracked file descriptor
SEC("tracepoint/syscalls/sys_enter_write")
int handle_write(struct trace_event_raw_sys_enter_write *ctx) {
    int pid = bpf_get_current_pid_tgid() >> 32;
    if (pid != my_pid) return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bpf_printk("bpf_ringbuf_reserve failed");
        return 0;
    }

    e->event_type = EVENT_WRITE;
    e->fd = ctx->fd;
    e->count = ctx->count;
    uint32_t buff_size = ctx->count > sizeof(e->buffer) ? sizeof(e->buffer) : ctx->count;
    bpf_probe_read(e->buffer, buff_size, (void *)ctx->buf);
    bpf_ringbuf_submit(e, 0);

    bpf_printk("Write detected on fd=%d, count=%d, buf=%s", ctx->fd, ctx->count, ctx->buf);
    return 0;
}


SEC("tracepoint/syscalls/sys_enter_pwrite64")
int handle_enter_pwrite64(struct trace_event_raw_sys_enter_pwrite64 *ctx) {
    int pid = bpf_get_current_pid_tgid() >> 32;
    //bpf_printk("write triggered my_fd=%d pid=%d\n", my_fd, my_pid);
    // TODO: use tgid as the map id

    if (pid != my_pid || ctx->fd < 3) return 0;

    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bpf_printk("error: failed to reserve space in ringbuffer.");
        return 0;
    }

    // populate and send event data
    e->event_type = EVENT_WRITE;
    e->fd = ctx->fd;

    uint32_t buff_size = ctx->count > sizeof(e->buffer) ? sizeof(e->buffer) : ctx->count;

    //uint32_t buff_size;
    //buff_size = ctx->count > MAX_BUFFER_LEN ? MAX_BUFFER_LEN : ctx->count;
    e->count = buff_size;
    e->offset = ctx->pos;
    bpf_probe_read(&e->buffer, buff_size, (void *) ctx->buf);
    bpf_ringbuf_submit(e, 0);

    bpf_printk("BPF triggered from pwrite64 enter, fd=%d count=%u, pos=%u, buf=%s.",
        ctx->fd, ctx->count, ctx->pos, ctx->buf);
    //bpf_printk("    + buf=%s.", ctx->buf);
        return 0;
}


// Tracepoint for syscall entry
SEC("tracepoint/syscalls/sys_enter_writev")
int handle_enter_writev(struct trace_event_raw_sys_enter_writev *ctx) {
    int pid = bpf_get_current_pid_tgid() >> 32;

    if (pid != my_pid) {
        return 0;
    }

    bpf_printk("writev triggered");
    
       uint64_t count = ctx->count;
    struct iovec *iov_array = (struct iovec *)ctx->iov;

    //print count
    bpf_printk("count:%llu", count);
    bpf_printk("IOV=%llu", iov_array);

    //loop through iov structures
    for (int i = 0; i < count; i++) {
        struct iovec iov;

	//bpf_printk("iov[%llu]: base=%p, len=%llu", i, iov.iov_base, iov.iov_len);
    }

    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_pwritev")
int handle_enter_pwritev(void *ctx) {
        int pid = bpf_get_current_pid_tgid() >> 32;

        if (pid != my_pid)
                return 0;

        bpf_printk("BPF triggered from pwritev.");

        return 0;
}

SEC("tracepoint/syscalls/sys_enter_pwritev2")
int handle_enter_pwritev2(void *ctx) {
        int pid = bpf_get_current_pid_tgid() >> 32;

        if (pid != my_pid)
                return 0;

        bpf_printk("BPF triggered from pwritev2.");

        return 0;
}


/*SEC("tracepoint/syscalls/sys_enter_pwritev2")
int handle_enter_pwritev2(void *ctx) {
        int pid = bpf_get_current_pid_tgid() >> 32;

        if (pid != my_pid)
                return 0;

        bpf_printk("BPF triggered from pwritev2.");

        return 0;
}*/
