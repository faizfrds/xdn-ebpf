#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "minimal.skel.h"
#include "common.h"

static volatile bool exiting = false;
char statediff_filename[MAX_BUFFER_LEN];
char statediff_buffer[MAX_BUFFER_LEN];
int statediff_fd = -1;
char *sd_logs = (char*) "/tmp/statediff";

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

void bump_memlock_rlimit(void) {
        struct rlimit rlim_new = {
                .rlim_cur       = RLIM_INFINITY,
                .rlim_max       = RLIM_INFINITY,
        };

        if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
                fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
                exit(1);
        }
}


int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct event *e = data;
    
    
    printf("statediff buffer=%s filename=%s\n", statediff_buffer, statediff_filename);
    //append to sd_logs file
    FILE *sd_file = fopen(sd_logs, "a");
    if (sd_file == NULL) {
            fprintf(stderr, "failed to open target sd_logs file\n");
            return 0;
    }

    //writing captured logs to sd_logs
    switch (e->event_type) {
        case EVENT_OPENTER:
            strncpy(statediff_filename, e->filename, sizeof(statediff_filename) - 1);
	    fprintf(sd_file, "OPENTER %s\n", e->filename);
            break;
	case EVENT_OPEN:
            fprintf(sd_file, "OPEN %ld\n", e->fd);
            break;
	case EVENT_WRITE:
	    strncpy(statediff_buffer, e->buffer, e->count);
            fprintf(sd_file, "WRITE %lu %lu %s\n", e->count, e->offset, e->buffer);
            break;
        default:
            fprintf(stderr, "Unknown event type: %d\n", e->event_type);
            break;
    }
    
    //ensuring any data left in the buffer is flushed out to sd_logs
    fflush(sd_file);
    return 0;
}

int main(int argc, char **argv)
{
    struct minimal_bpf *skel;
    int err, target_pid;
    struct ring_buffer *rb = NULL;

    if (argc < 2) {
        fprintf(stderr, "PID is required\n");
        printf("usage: ./sdcapture <pid>\n");
        return 1;
    }

    libbpf_set_print(libbpf_print_fn);
    bump_memlock_rlimit();   
    
    skel = minimal_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    target_pid = atoi(argv[1]); //fetching parameter

    skel->bss->my_pid = target_pid; //assigning skeleton pid to target pid

    err = minimal_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    err = minimal_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    printf("PID=%d\n", skel->bss->my_pid);
    printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
           "to see output of the BPF programs.\n");

    //ring buffer setup
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    //empty the sd_logs file from previous writes and start new
    FILE *sd_file = fopen(sd_logs, "w");
    if (sd_file == NULL) {
        fprintf(stderr, "Failed to open /tmp/statediff for clearing\n");
        goto cleanup;
    }
    fclose(sd_file);  // Closing the file immediately after truncating it
		      //
    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }

        sleep(1);
    }

cleanup:
    //close(fd);
    minimal_bpf__destroy(skel);
    ring_buffer__free(rb);
    return -err;
}

