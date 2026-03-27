/*
 * Copyright (C) 2026 Maurice Green
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef KBPF_KVM_LATENCY_H
#define KBPF_KVM_LATENCY_H

#include "vmlinux.h"
#include "bpf_kvm_common.h"

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#define TLB_FLUSH_CURRENT   26
#define TLB_FLUSH_GUEST     27
#define TLB_FLUSH_HV        32

/* directly calls the `requests` bitmap helper */
int check_exit_tlb_any(__u64 *req_map);

/* checks if TLB bit is set in vcpuid->requests bitmap */
static __always_inline int __check_exit_tlb_bit(__u64 *req_map, int bit);

/* vcpuid->requests bitmap helper */
static inline struct exit_event create_exit_event(__u64 reqmap, 
                                        __u32 tid, __u32 vcpuid);

struct exit_event
{
    __u64 vcpu_requests;
    __u32 hypercall_nr;
    __u64 start_ts;
    __u8 tlbflush;
    __u32 vcpuid;
    __u32 tid;
};

struct kvm_exit_entry
{
    __u32 exit_reason;
    __u32 guest_rip;
    __u32 isa;
    __u64 info1;
    __u64 info2;
    __u32 int_info;
    __u32 error_code;
    __u32 vcpu_id;
    __u64 requests;
};

struct kvm_hypercall_entry
{
    __u32 nr;
    __u32 a0;
    __u32 a1;
    __u32 a2;
    __u32 a3;
};

struct kvm_entry_sentry
{
    __u32 rip;
    __u8  kbool;
    __u32 vcpu_id;
    __u32 int_info;
    __u32 error_code;
};


#endif // KBPF_KVM_LATENCY_H