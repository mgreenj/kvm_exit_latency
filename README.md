>[!NOTE]
> The contents of this README are also shared on my blog site.
> To learn more about me,
>   Visit my landing page @[mauricegreen.me](https://mauricegreen.me)
>   to learn more about me, and visit my blog, [The Code Guardian](https://blog.mauricegreen.me/blogs/).


# KVM Guest Exit Latency
Harware-assisted virtualization allows vm guests to switch from guest mode to a `root` mode when the execution of cpu instructions is needed. There is no requirement to translate unpriviledge guest code to privileged code, as with software-assisted virtualization. This exit, however, can be costly and measuring the
latency of an exit can provide meaningful information.

This program enables administrators to measure the latency of KVM Guest machines, by tracing the following events:
 - kvm_exit
 - kvm_hypercall
 - kvm_entry

Looking at linux/arch/x86/kvm/trace.h, you will can find the necessary information for program context, depending on trace program type. TP_STRUCT_entry is the context used for this tracepoint type. Raw Tracepoints could use TP_PROTO/TP_ARGS, fentry would use the arguments of the underlying function being traced. kprobe contexts can use BTF format.

## KVM Hypercall
A hypercall is similar to a syscall, however, instead of being handled by the kernel, hypercalls are handled by the hypervisor. When the guest needs to run a privileged instruction, it uses a hypercall to pass args to the hypervisor.

## VMCALL Instruction

`VMCALL` is an instruction that allows guest software to make a call for service to the VMM (Virtual Machine Monitor), also referred to as a hypervisor. It belongs to the VMX (Virtual Machine Extention / VT-x) hardware extension included in Intel CPUs.

## KVM Request

The request passed to the kvm hypervisor is stored in vcpu->requests, which is a bitmap that can be explored further in arch/x86/include/asm/kvm_host.h

This the `request` member is a 64-bit unsigned integer, however, as far as I can tell, it only uses 34 bits. Here are a few interresting bits.

```
KVM_REQ_LOAD_MMU_PGD
KVM_REQ_CLOCK_UPDATE
KVM_REQ_EVENT
KVM_REQ_TLB_FLUSH_CURRENT
```

My eBPF program includes the following code to demonstrate how this bitmap can be used. I hope to update program to include more advanced mechanisms and provide more meaningful insight.

```
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

static inline struct exit_event create_exit_event(__u64 reqmap, 
                                        __u32 pid, __u32 vcpuid)
{
    struct exit_event exit = {
        .start_ts = bpf_ktime_get_ns(),
        .vcpuid = vcpuid,
        .vcpu_requests = reqmap,
        .pid = pid,
        .tlbflush = check_exit_tlb_any(&reqmap) ? true : false
    };

    return exit;
}

```

## Example Usage

### Run Qemu VM
```
 |py-3.14.2| fedora in ~/vm_env
○ → sudo qemu-system-x86_64   -enable-kvm   -m 512M   -smp 1   -cdrom alpine-virt-3.23.3-x86_64.iso   -boot d   -nographic
[sudo] password for mgre2324:
SeaBIOS (version 1.17.0-9.fc43)


iPXE (https://ipxe.org) 00:03.0 CA00 PCI2.10 PnP PMM+1EFCBE10+1EF0BE10 CA00



Booting from DVD/CD...

ISOLINUX 6.04 6.04-pre1 ETCD Copyright (C) 1994-2015 H. Peter Anvin et a
ISOLINUX 6.04 6.04-pre1  Copyright (C) 1994-2015 H. Peter Anvin et al
l
boot:boot:

Welcome to Alpine Linux 3.23
Kernel 6.18.7-0-virt on x86_64 (/dev/ttyS0)

localhost login: root
Welcome to Alpine!
```

### Run eBPF Program
```
 |py-3.14.2| fedora in ~/kvm_exit_latency
± |master {1} ?:3 ✗| → sudo ./spekt
[sudo] password for mgre2324:
libbpf: elf: skipping unrecognized data section(13) author
THREAD     | HC_NR  | LATENCY (ns)
---------------------------------------------
TID: 9937   | HC_NR: 0   | Latency: 6156 ns
TID: 9937   | HC_NR: 0   | Latency: 2669 ns
TID: 9937   | HC_NR: 0   | Latency: 1445 ns
TID: 9937   | HC_NR: 0   | Latency: 990 ns
TID: 9937   | HC_NR: 0   | Latency: 1664 ns
TID: 9937   | HC_NR: 0   | Latency: 2079 ns
TID: 9937   | HC_NR: 0   | Latency: 13932 ns
TID: 9937   | HC_NR: 0   | Latency: 5136 ns
TID: 9937   | HC_NR: 0   | Latency: 4832 ns
TID: 9937   | HC_NR: 0   | Latency: 1337 ns
TID: 9937   | HC_NR: 0   | Latency: 2199 ns
TID: 9937   | HC_NR: 0   | Latency: 161223 ns
```