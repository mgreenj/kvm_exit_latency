/**
 * Author: Maurice Green
 * Purpose: eBPF Kernel Program
 * 
 */

#include "kbpf_kvm_latency.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct exit_event);
    __uint(max_entries, 10240);
} start_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

static __always_inline int __check_exit_tlb_bit(__u64 *req_map, int bit)
{
    // checking if KVM_REQ_TLB_FLUSH_CURRENT
    return (*req_map & (1ULL << bit));
}

int check_exit_tlb_any(__u64 *req_map)
{
    return __check_exit_tlb_bit(req_map, TLB_FLUSH_CURRENT) || 
           __check_exit_tlb_bit(req_map, TLB_FLUSH_GUEST) || 
           __check_exit_tlb_bit(req_map, TLB_FLUSH_HV);
}

/* inlining here to make the call to bpf_ktime_get_ns as close
as possible to exit event w/o call overhead */
static inline struct exit_event create_exit_event(__u64 reqmap, 
                                        __u32 tid, __u32 vcpuid)
{
    struct exit_event exit = {
        .start_ts = bpf_ktime_get_ns(),
        .vcpuid = vcpuid,
        .vcpu_requests = reqmap,
        .tid = tid,
        .tlbflush = check_exit_tlb_any(&reqmap) ? true : false
    };

    return exit;
}

SEC("raw_tracepoint/kvm_exit")
int handle_kvm_exit(struct bpf_raw_tracepoint_args *ctx)
{
    /* Thread ID of the host cpu that handles the exit
    will be the same thread used for hypercall and entry */
    __u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    bpf_printk("EXIT: tid=%u", tid);

    struct kvm_vcpu *vcpu = (void *)ctx->args[0];

    // vmx `vmcall` instruction, guest calls vmm
    // if (vcpu->exit_reason != EXIT_REASON_VMCALL)
    //     return 0;

    __u32 vcpuid = BPF_CORE_READ(vcpu, vcpu_id);
    __u64 req = BPF_CORE_READ(vcpu, requests);

    struct exit_event e = create_exit_event(
                          req, tid, vcpuid);

    bpf_map_update_elem(&start_map, &tid, &e,
                                    BPF_ANY);

    return 0;
}

SEC("raw_tracepoint/kvm_hypercall")
int handle_kvm_hypercall(struct bpf_raw_tracepoint_args *ctx)
{
    __u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    struct exit_event *e = bpf_map_lookup_elem(&start_map, &tid);

    if (e)
        e->hypercall_nr = ctx->args[0];
    return 0;
}

SEC("raw_tracepoint/kvm_entry")
int handle_kvm_entry(struct bpf_raw_tracepoint_args *ctx)
{
    __u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;;
    struct exit_event *e = bpf_map_lookup_elem(&start_map,
                                                    &tid);
    
    if (e) {
        bpf_printk("ENTRY: Match found for tid=%u", tid);

        struct sq_data *seq_data;
        __u64 end_ts = bpf_ktime_get_ns();

        /** 
         * data not in memory, cannot use bpf_ringbuf_output
         * also, this memory does not count toward stack. I 
         * like using this instead of bpf_ringbuf_output when
         * I know the exact amount of memory needed. Verifier 
         * asserts that this this reserved space is not overrun,
         * violation will be rejecting
         */

        /* using the variable name (i.e., sizeof(*seq_data) for 
        type safety, to avoid bugs if struct type is changed*/ 
        seq_data = bpf_ringbuf_reserve(&rb, sizeof(*seq_data), 0);
        if (seq_data) {
            seq_data->tid = tid;
            seq_data->nr = e->hypercall_nr;
            seq_data->latency_ns = end_ts - e->start_ts;
            bpf_ringbuf_submit(seq_data, 0);
        }
        bpf_map_delete_elem(&start_map, &tid);
    }
    bpf_printk("Leaving: Entry Event tid=%u", tid);
    return 0;
}

__u32 VERSION SEC("version") = 1;
char LICENSE[] SEC("license") = "GPL";
char AUTHOR[] SEC("author") = "Maurice";