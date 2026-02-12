/**
 * Author: Maurice Green
 * Purpose: eBPF User Program
 * 
 */

#include "ubpf_kvm_latency.h"
#include "kvm_latency.skel.h"

static int stop = 0;
void handle_sig(int sig) { stop = 1; }

int handle_event(void *ctx, void *data, size_t data_sz) {
    
    struct sq_data *e = data;

    // Added \n and explicitly formatted for your data_t fields
    printf("TID: %-6u | HC_NR: %-3u | Latency: %lu ns\n", 
            e->tid, e->nr, e->latency_ns);
    
    fflush(stdout);
    return 0;
}

int main(void)
{
    struct kvm_latency_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    signal(SIGINT, handle_sig);
    
    skel = kvm_latency_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    err = kvm_latency_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("%-10s | %-6s | %-12s\n", "THREAD", "HC_NR", "LATENCY (ns)");
    printf("---------------------------------------------\n");

    while (!stop) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) {
            break;
        }
        if (err < 0) {
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    kvm_latency_bpf__destroy(skel);
    return 0;
}