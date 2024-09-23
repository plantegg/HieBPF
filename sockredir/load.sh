#!/bin/bash

# enable debug output for each executed command
# to disable: set +x
set -x
# exit if any command fails
set -e

# Mount the bpf filesystem
#sudo mount -t bpf bpf /sys/fs/bpf/
#mkdir -p /tmp/unified
#sudo mount -t cgroup2 none /tmp/unified

# Compile the bpf_sockops_v4 program
clang -O2 -g -target bpf  -I.output/ -I../../libbpf/include/uapi -I../../vmlinux/x86/ -I/root/bpf/libbpf-bootstrap/blazesym/capi/include -c tcp_bypass_ops.bpf.c -o tcp_bypass_ops.bpf.o

# Load and attach the bpf_sockops_v4 program
bpftool prog load tcp_bypass_ops.bpf.o "/sys/fs/bpf/bpf_sockops"
bpftool cgroup attach "/tmp/unified/" sock_ops pinned "/sys/fs/bpf/bpf_sockops"
#bpftool cgroup attach /run/sockops/ sock_ops id XXX


# Extract the id of the sockhash map used by the bpf_sockops_v4 program
# This map is then pinned to the bpf virtual file system
MAP_ID=$(bpftool prog show pinned "/sys/fs/bpf/bpf_sockops" | grep -o -E 'map_ids [0-9]+' | cut -d ' ' -f2-)
bpftool map pin id $MAP_ID "/sys/fs/bpf/sock_ops_map"

# Load and attach the bpf_tcpip_bypass program to the sock_ops_map
 clang -O2 -g -target bpf  -I.output/ -I../../libbpf/include/uapi -I../../vmlinux/x86/ -I/root/bpf/libbpf-bootstrap/blazesym/capi/include -c tcp_bypass.bpf.c -o tcp_bypass.bpf.o
bpftool prog load tcp_bypass.bpf.o "/sys/fs/bpf/tcp_bypass" map name sock_ops_map pinned "/sys/fs/bpf/sock_ops_map"
bpftool prog attach pinned "/sys/fs/bpf/tcp_bypass" msg_verdict pinned "/sys/fs/bpf/sock_ops_map"
