# Socket data redirection using eBPF

## 功能

这是一个Hello world 级别的 ebpf 程序，适合当作初学者的入门

主要功能是实现如果是 localhost 本地通信，就让 send_message 直接发给另外一个进程的 接收 buff，绕过内核协议栈，提升性能，实现真正的本地通信



经过测试性能会有 15% 的提升，代码简单使用场景广泛，比如在容器/微服务场景大量 POD 共享一个网络栈，或者多个进程跑在同一台机器上他们之间通信的时候还是需要走完完整的网络协议栈



## 实现

1. 通过 SEC("sockops") 监听所有连接的建立，如果是本机通信就将这个 socket 记录到一个 map(socks_map)
2. 如果有进程调用 SEC("sk_msg") 发送消息，就和上面的 map 比对，如果命中说明是本机通信，就绕过内核协议栈，直接通过内核函数 bpf_msg_redirect_hash 将要发送的内容从发送端的 socket buffer 复制到接收端(本机的另外一个 socket) buffer



原始程序和分析来源这篇博客： [How to use eBPF for accelerating Cloud Native applications ](https://cyral.com/blog/how-to-ebpf-accelerating-cloud-native/)  原始代码仓库：https://github.com/cyralinc/os-eBPF.git

可惜的是这篇文章和代码都是 2020 年的，而这几年 ebpf 的变化非常大，内核对 ebpf 的支持不断增加，所以实现上偏老化了，但这个场景仍然是入门的最佳实践



所以接下来，把这段老代码进行改写，把这个过程当成初学 ebpf 的 HelloWorld，并记录下



## 过程

### 环境

还是星球 99 块的 ECS，安装基本的 bpf 运行依赖等，这次略过，或者网上搜一下

```
yum install -y clang elfutils-libelf elfutils-libelf-devel zlib-devel bpftool

#uname -r
5.10.134-15.al8.x86_64

#rpm -qa |grep bpf
libbpf-0.6.0-1.1.al8.x86_64
bpftool-5.10.134-15.al8.x86_64
bpftrace-0.16.0-6.2.al8.x86_64
```



### 原始程序运行不了

略微改改后终于可以跑起来了：https://github.com/plantegg/HieBPF  develop 分支

### 按照 libbpf-bootstrap 改写

能跑，但是 两个 bpf 程序的 map 不共享，导致 sk_msg 的时候不会转发，仍然走了内核协议栈，见  skel-bootstrap 分支

虽然没达到目的，但是这个过程学到的东西最多/碰到的问题也最多，收获很大，所以放出来

### 最终可用

将两个 bpf 合并到一个 bpf，就可以实现转发了，在上一步的基础上不需要额外修改代码，见 ok-bootstrap 分支



## 测试

先 clone https://github.com/libbpf/libbpf-bootstrap.git  然后 clone 本仓库，将本仓库挪到 libbpf-bootstrap/examples/ 下，然后执行 make

说明：

make 时先要 make libbpf，实际我们不会修改 libbpf 所以只需要第一次 make libbpf, 后面不删 libbpf 就行，后面的 make 只需要编译我们自己的代码就快多了

第一次 make 的时候还会编译出 bpftool 等工具(为了兼容性更好)

通过 bpftool gen skel 会自动帮我们生成一些 c 语言的 skel 代码，封装了 bpftoo prog load/ bpftool prog attach 在 skel 中

最后我们自己会通过 tcp_bypass.c 用 libbpf 的 API 来完成 load.sh 中的动作 



可以用仓库自带的脚本测试，也可以在本地用 sysbench 压 MySQL 进行验证，测试验证对性能提升非常明显



--------------

> This is BPF code that demonstrates how to bypass TCPIP for socket data without modifying the applications. This code is a companion to this [blog](https://cyral.com/blog/how-to-ebpf-accelerating-cloud-native) post. 

The goal of this project is to show how to setup an eBPF network acceleration using socket data redirection when the communicating apps are on the same host.


## Testing

A simple bash script [load.sh](https://github.com/cyralinc/os-eBPF/blob/develop/sockredir/load.sh) is included that performs the following tasks:

1. Compiles the sockops BPF code, using LLVM Clang frontend, that updates the sockhash map
2. Uses bpftool to attach the above compiled code to the cgroup so that it gets invoked for all the socket operations such as connection established, etc. in the system.
3. Extracts the id of the sockhash map created by the above program and pins the map to the virtual filesystem so that it can be accessed by the second eBPF program 
4. Compiles the tcpip_bypass code that performs the socket data redirection bypassing the TCPIP stack
5. Uses bpftool to attach the above eBPF code to sockhash map 

After running the script you should be able to verify the eBPF program is loaded in the kernel.

### Verifying BPF programs are loaded in the kernel

You can list all the BPF programs loaded and their map ids:

```bash
#sudo bpftool prog show
99: sock_ops  name bpf_sockops_v4  tag 8fb64d4d0f48a1a4  gpl
	loaded_at 2020-04-08T15:54:36-0700  uid 0
	xlated 688B  jited 399B  memlock 4096B  map_ids 45
103: sk_msg  name bpf_tcpip_bypas  tag 550f6d3cfcae2157  gpl
	loaded_at 2020-04-08T15:54:36-0700  uid 0
	xlated 224B  jited 151B  memlock 4096B  map_ids 45
```

You should be able to view the SOCKHASH map also pinned onto the filesystem:

```bash
#sudo tree /sys/fs/bpf/
/sys/fs/bpf/
├── bpf_sockops
├── bpf_tcpip_bypass
└── sock_ops_map

0 directories, 3 files


#sudo bpftool map show id 45 -f
45: sockhash  name sock_ops_map  flags 0x0
	key 24B  value 4B  max_entries 65535  memlock 0B
```

### Verifying application programs are bypassing the TCPIP stack

#### Turn on tracing logs (if not enabled by default)
```bash
#echo 1 > /sys/kernel/debug/tracing/tracing_on
```
#### You can cat the kernel live streaming trace file, trace_pipe, in a shell to monitor the trace of the TCP communication through eBPF
```bash
#cat /sys/kernel/debug/tracing/trace_pipe
nc-1935  [000] ....   840.199017: 0: <<< ipv4 op = 4, port 48712 --> 1000
nc-1935  [000] .Ns1   840.199043: 0: <<< ipv4 op = 5, port 1000 --> 48712
```

#### We can use a TCP listener spawned by SOCAT to mimic an echo server, and netcat to sent a TCP connection request.
```bash
sudo socat TCP4-LISTEN:1000,fork exec:cat
nc localhost 1000 # this should produce the trace in the kernel file trace_pipe
```

## Cleanup

Running the [unload.sh](https://github.com/cyralinc/os-eBPF/blob/develop/sockredir/unload.sh) script detaches the eBPF programs from the hooks and unloads them from the kernel.

## Building

You can build on any Linux kernel with eBPF support. We have used Ubuntu Linux 18.04 with kernel 5.3.0-40-generic

## Ubuntu Linux

To prepare a Linux development environment for eBPF development, various packages and kernel headers need to be installed. Follow the following steps to prepare your development environment:
1. Install Ubuntu 18.04
2. sudo apt-get install -y make gcc libssl-dev bc libelf-dev libcap-dev clang gcc-multilib llvm libncurses5-dev git pkg-config libmnl-dev bison flex graphviz
3. sudo apt-get install iproute2
4. Download the Linux kernel source
	1. You will need to update source URIs in /etc/apt/source.list
	2. Perform the following:
		```bash
		sudo apt-get update
		sudo apt-get source linux-image-$(uname -r)
		```
		If it fails to download the source, try:
		```bash
		sudo apt-get source linux-image-unsigned-$(uname -r)
		```
	3. More information on Ubuntu [wiki](https://wiki.ubuntu.com/Kernel/BuildYourOwnKernel)
5. We will use the UAPI $kernel_src_dir/include/uapi/linux/bpf.h in the eBPF code
6. Compile and install bpftool from source. It is not yet packaged as part of the standard distributions of Ubuntu. 
	1. cd $kernel_src_dir/tools/bpf/bpftools
	2. make 
	3. make install.
7. You might also need to install libbfd-dev
