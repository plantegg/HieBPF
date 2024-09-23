#!/bin/bash
set -x

# Detach and unload the sockops.o program
bpftool cgroup detach "/run/unified/" sock_ops pinned "/sys/fs/bpf/sockops"
rm "/sys/fs/bpf/sockops"
