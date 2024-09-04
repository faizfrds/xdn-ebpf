/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2023 Fadhil I. Kurnia */
#ifndef __COMMON_H
#define __COMMON_H

#include <string.h>
#include <stdint.h>

#define TASK_COMM_LEN    16
#define MAX_BUFFER_LEN   4096
#define MAX_FILENAME_LEN 256

struct trace_event_raw_sys_enter_open {
	uint64_t    unused;			// 8 bytes
	int64_t     __syscall_nr;	// 4 bytes + 4 bytes padding
    char        *filename;		// 8 bytes
    uint64_t    flags;		    // 8 bytes
    uint64_t    mode;		    // 8 bytes
};

struct trace_event_raw_sys_enter_openat {
	uint64_t    unused;			// 8 bytes
	int64_t     __syscall_nr;	// 4 bytes + 4 bytes padding
    uint64_t    dfd;	        // 8 bytes
    char        *filename;		// 8 bytes
    uint64_t    flags;		    // 8 bytes
    uint64_t    mode;		    // 8 bytes
};

struct trace_event_raw_sys_enter_close {
	uint64_t    unused;			// 8 bytes
	int64_t     __syscall_nr;	// 4 bytes + 4 bytes padding
    uint64_t    fd;		        // 8 bytes
};

struct trace_event_raw_sys_exit_int64 {
	uint64_t    unused;			// 8 bytes
	int64_t     __syscall_nr;	// 4 bytes + 4 bytes padding
    int64_t     ret;		    // 8 bytes, fd or -1 for error
};

struct trace_event_raw_sys_enter_pwrite64 {
	uint64_t    unused;			// 8 bytes, long long is at least 64-bit
	int64_t     __syscall_nr;	// 4 bytes + 4 bytes padding
    uint64_t    fd;				// 8 bytes
    const char  *buf;			// 8 bytes
    uint64_t    count;			// 8 bytes
    uint64_t    pos;			// 8 bytes
};

struct trace_event_raw_sys_exit_pwrite64 {
	uint64_t    unused;			// 8 bytes, long long is at least 64-bit
	int64_t     __syscall_nr;	// 4 bytes + 4 bytes padding
    int64_t     ret;		    // 8 bytes, count of written data
};

struct trace_event_raw_sys_enter_write {
	uint64_t    unused;			// 8 bytes, long long is at least 64-bit
	int64_t     __syscall_nr;	// 4 bytes + 4 bytes padding
    uint64_t    fd;				// 8 bytes
    const char  *buf;			// 8 bytes
    uint64_t    count;			// 8 bytes

};

struct iovec {
    void *iov_base;  // Pointer to data
    size_t iov_len;  // Length of data
};

// Define the trace event structure for `writev`
struct trace_event_raw_sys_enter_writev {
    uint64_t filedes;       // File descriptor
    uint64_t iov;      // Pointer to the `iovec` array
    uint64_t count;    // Number of `iovec` structures
};

enum event_t {
    RESERVED,
    EVENT_WRITE,
    EVENT_OPEN,
    EVENT_OPENTER,
    EVENT_UNLINK
};

/* definition of a sample sent to user-space from BPF program */
struct event {
    uint8_t  event_type;
    uint64_t fd;
    uint64_t count;
    uint64_t offset;
    char     filename[128];              // 8 bytes
    char     buffer[MAX_BUFFER_LEN];
    uint8_t  is_socket;
};

// Workaround: Newer LLVM versions might fail to optimize has_prefix()
// loop unrolling with the following error:
//
//     warning: loop not unrolled: the optimizer was unable to perform
//     the requested transformation; the transformation might be
//     disabled or specified as part of an unsupported transformation
//     ordering
//

#if defined(__clang__) && __clang_major__ > 13

    #define has_prefix(p, s, n)                                                \
        ({                                                                     \
            int rc = 0;                                                        \
            char *pre = p, *str = s;                                           \
            _Pragma("unroll") for (int z = 0; z < n; pre++, str++, z++)        \
            {                                                                  \
                if (!*pre) {                                                   \
                    rc = 1;                                                    \
                    break;                                                     \
                } else if (*pre != *str) {                                     \
                    rc = 0;                                                    \
                    break;                                                     \
                }                                                              \
            }                                                                  \
            rc;                                                                \
        })

#else

static __inline int has_prefix(char *prefix, char *str, int n)
{
    int i;
    #pragma unroll
    for (i = 0; i < n; prefix++, str++, i++) {
        if (!*prefix)
            return 1;
        if (*prefix != *str) {
            return 0;
        }
    }

    // prefix is too long
    return 0;
}

#endif

#endif /* __COMMON_H */
