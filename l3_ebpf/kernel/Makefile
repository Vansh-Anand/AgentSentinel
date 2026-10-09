CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPF_TARGET = bpf

# If vmlinux.h is not present locally, dump it from running kernel
# bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

all: execve.bpf.o libnative_loader.so

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@.tmp
	mv $@.tmp $@

execve.bpf.o: execve.bpf.c events.h vmlinux.h
	$(CLANG) -g -O2 -target $(BPF_TARGET) -D__TARGET_ARCH_x86 -c $< -o $@
	$(LLVM_STRIP) -g $@

libnative_loader.so: ../userspace/native_loader.c
	$(CC) -O2 -fPIC -shared -o $@ $< -lbpf -lelf -lz

clean:
	rm -f *.bpf.o *.so
