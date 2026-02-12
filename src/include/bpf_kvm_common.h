/**
 * Author: Maurice Green
 * Purpose: Definitions shared by both eBPF programs
 * 
 */

#ifndef BPF_KVM_COMMON_H
#define BPF_KVM_COMMON_H

struct sq_data {
    uint64_t latency_ns;
    uint32_t tid;
    uint32_t nr;
} __attribute__((packed));

#endif // BPF_KVM_COMMON_H