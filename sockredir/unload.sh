#!/bin/bash
set -x

# Detach and unload the tcp_bypass program
bpftool prog detach pinned "/sys/fs/bpf/tcp_bypass" msg_verdict pinned "/sys/fs/bpf/sock_ops_map"
sudo rm "/sys/fs/bpf/tcp_bypass"

# Detach and unload the bpf_sockops_v4 program
bpftool cgroup detach "/tmp/unified/" sock_ops pinned "/sys/fs/bpf/bpf_sockops"
sudo rm "/sys/fs/bpf/bpf_sockops"

# Delete the map
sudo rm "/sys/fs/bpf/sock_ops_map"
