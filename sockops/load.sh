#!/bin/bash

# enable debug output for each executed command
# to disable: set +x
set -x
# exit if any command fails
set -e

# Mount the bpf filesystem
#mkdir -p /run/unified
#sudo mount -t cgroup2 none /run/unified

# Compile the bpf_sockops_v4 program
clang -O2 -g -I.output -I../../libbpf/include/uapi -I../../vmlinux/arm64/ -I/root/libbpf-bootstrap/blazesym/capi/include -idirafter /usr/lib/llvm-18/lib/clang/18/include -idirafter /usr/local/include -idirafter /usr/include/aarch64-linux-gnu -idirafter /usr/include -target bpf -c sockops.bpf.c -o .output/sockops.o

#attach命令支持多种flag，默认flag为0,bpftool就是用的 0
#link_create命令只支持其中的一个flag:BPF_F_ALLOW_MULTI
#bpftool cgroup attach "/run/bpf-cgroup2" sock_ops pinned "/sys/fs/bpf/bpf_sockops1" multi 
#列出已经 attach 的 cgroup bpf 程序
#bpftool cgroup list /run/unified/ 

# Load and attach the sockops program
bpftool prog load .output/sockops.o "/sys/fs/bpf/sockops"
bpftool cgroup attach "/run/unified/" sock_ops pinned "/sys/fs/bpf/sockops"

