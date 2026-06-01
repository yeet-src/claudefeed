.PHONY: all clean

ARCH    ?= $(shell uname -m | sed 's/x86_64/x86/; s/aarch64/arm64/')
CLANG   ?= clang
BPFTOOL ?= sudo bpftool

# Prefer the bpf headers that ship with libbpf-sys (so this builds without
# system libbpf-dev). Fall back to /usr/include if the libbpf-sys build
# artifact isn't around.
LIBBPF_INCLUDE := /usr/include

CFLAGS = -O2 -g -Wall -target bpf \
         -D__TARGET_ARCH_$(ARCH) \
         -I. -Iinclude -I$(LIBBPF_INCLUDE)

all: claudefeed.bpf.o

# The tracepoint context structs, task_struct, and socket structs all
# come from BTF.
include/vmlinux.h:
	@mkdir -p include
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

claudefeed.bpf.o: claudefeed.bpf.c include/vmlinux.h
	$(CLANG) $(CFLAGS) -c $< -o $@

clean:
	rm -f claudefeed.bpf.o include/vmlinux.h
