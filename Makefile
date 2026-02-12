CLANG := clang
BPFTOOL := bpftool
CFLAGS := -g -O2 -Wall
BPF_CFLAGS := -target bpf -D__TARGET_ARCH_x86

SRC_DIR := src
INC_DIR := $(SRC_DIR)/include
BPF_SRC := $(SRC_DIR)/kvm_latency.bpf.c
BPF_OBJ := $(SRC_DIR)/kvm_latency.bpf.o
BPF_SKEL := $(INC_DIR)/kvm_latency.skel.h
VMLINUX := $(INC_DIR)/vmlinux.h

USER_SRC := kvm_latency_user.c
TARGET := spekt

COMMON_H := $(INC_DIR)/bpf_kvm_common.h
K_H := $(INC_DIR)/kbpf_kvm_latency.h
U_H := $(INC_DIR)/ubpf_kvm_latency.h

.PHONY: all clean run

all: $(TARGET)

$(VMLINUX):
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BPF_OBJ): $(BPF_SRC) $(VMLINUX) $(COMMON_H) $(K_H)
	$(CLANG) $(BPF_CFLAGS) $(CFLAGS) -I$(INC_DIR) -c $< -o $@

$(BPF_SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

$(TARGET): $(USER_SRC) $(BPF_SKEL) $(COMMON_H) $(U_H)
	$(CLANG) $(CFLAGS) -I$(INC_DIR) $< -lbpf -lelf -lz -o $@

run: $(TARGET)
	sudo ./$(TARGET)

clean:
	rm -f $(BPF_OBJ) $(BPF_SKEL) $(VMLINUX) $(TARGET)