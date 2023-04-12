APPS = capable
.PHONY: all
all: $(APPS)
$(APPS):
	clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu -I. -c $@.bpf.c -o $@.bpf.o
vmlinux:
	$(bpftool) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
