# 修改 Socket 参数

## 目的

通过动态修改socket options 的参数，比如初始拥塞窗口大小是 10，对一些大数据传输场景我们希望一上来有更大的初始窗口，避免较长的慢启动，那么可以针对某些端口/ip 设置一个更大的初始窗口

## 运行

1. 先下载 [libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap)  到本地: git clone --recurse-submodules git@github.com:libbpf/libbpf-bootstrap.git
2. 然后下载本程序放到 libbpf-bootstrap/examples/ 下
3. 执行 mkdir -p /run/unified ; sudo mount -t cgroup2 none /run/unified //提前创建 cgroup2 
4. cd libbpf-bootstrap/examples/sockops ; make，第一次时间较长，因为会先编译 libbpf-bootstrap 下的 libbpf 到当前 .output/ 目录
5. 在当前目录会生成一个 ./sockops 二进制可执行文件，执行这个文件
6. 执行命令：bpftool prog tracelog 观察 bpf 程序的日志输出
7. 本地启动一个端口：nc -l 4321/ 然后再启动一个客户端连这个 4321 端口：nc 192.168.104.4 4321
8. 能观察到 bpftool prog tracelog 日志输出
9. 通过命令 ss -mi 可以看到 4321 端口这个连接的初始窗口已经被设置为 99 了，本机上 bpf 程序启动前的连接的

```
# ss -mi 
tcp    ESTAB   0        0                                                   192.168.104.4:55120                  192.168.104.4:4321 //下面的 cwnd:10 表示拥塞窗口是默认值 ssthresh:999
	 skmem:(r0,rb246912,t0,tb246912,f0,w0,o0,bl0,d0) cubic wscale:7,1 rto:200 rtt:0.018/0.009 mss:32741 pmtu:65535 rcvmss:536 advmss:65483 cwnd:10 ssthresh:999 bytes_acked:1 segs_out:2 segs_in:1 send 146Gbps lastsnd:12143 lastrcv:12143 lastack:12143 pacing_rate 291Gbps delivered:1 app_limited rcv_space:65495 rcv_ssthresh:65495 minrtt:0.018 snd_wnd:65483
tcp    ESTAB   0        0                                                   192.168.104.4:4321                   192.168.104.4:55120 //下面的 cwnd:99 表示初始拥塞窗口被改成了 99
	 skmem:(r0,rb131072,t0,tb4194304,f0,w0,o0,bl0,d0) cubic wscale:1,7 rto:200 rtt:0.013/0.006 mss:32748 pmtu:65535 rcvmss:536 advmss:65483 cwnd:99 segs_in:2 send 2Tbps lastsnd:12143 lastrcv:12143 lastack:12143 pacing_rate 3.99Tbps delivered:1 app_limited rcv_space:65483 rcv_ssthresh:65483 minrtt:0.013 snd_wnd:65496
	 
	 
# bpftool prog tracelog //如下输出表示 bpf 程序在工作了(忽略日志里最后的 0)
// 字段<taskname>-<pid> <cpuid><opts> <timestamp>    <fake by bpf>  <log content>
              nc-21808   [000] b.s21 39394.929564: bpf_trace_printk: change socket options
              nc-21808   [000] ...11 39394.929572: bpf_trace_printk: change socket options
              nc-21808   [000] ..s31 39394.929593: bpf_trace_printk: change socket options
              nc-21808   [000] ..s31 39394.929593: bpf_trace_printk: change init cwnd: 99
              
#root@lima-bpf:~/libbpf-bootstrap/examples/sockops# ls -lhrt .output/  //编译输出
total 3.3M
drwxr-xr-x 3 root root 4.0K Sep 23 09:40 libbpf
drwxr-xr-x 2 root root 4.0K Sep 23 09:40 bpf
drwxr-xr-x 2 root root 4.0K Sep 23 09:40 pkgconfig
-rw-r--r-- 1 root root 3.2M Sep 23 09:40 libbpf.a
drwxr-xr-x 3 root root 4.0K Sep 23 09:40 bpftool
-rw-r--r-- 1 root root  13K Sep 23 09:49 sockops.tmp.bpf.o
-rw-r--r-- 1 root root 4.5K Sep 23 09:49 sockops.bpf.o
-rw-r--r-- 1 root root  19K Sep 23 09:49 sockops.skel.h
-rw-r--r-- 1 root root  26K Sep 23 09:49 sockops.o 

root@lima-bpf:~/libbpf-bootstrap/examples/sockops# ls -lhrt
total 1.5M
-rwxr-xr-x 1 ren  ren  1.2K Sep 18 16:57 load.sh
-rw-r--r-- 1 ren  ren  4.3K Sep 18 16:57 README.md
-rwxr-xr-x 1 ren  ren   427 Sep 18 16:57 unload.sh
-rw-r--r-- 1 ren  ren  4.5K Sep 20 14:47 Makefile
-rw-r--r-- 1 root root 1.6K Sep 23 09:07 sockops.c
-rw-r--r-- 1 root root 2.2K Sep 23 09:56 sockops.bpf.c
-rwxr-xr-x 1 root root 1.4M Sep 23 09:57 sockops  //最终用户态的可执行文件
```

## sockops.c

这是个用户态的程序，负责加载编译后的 sockops.bpf.c 到内核并执行 attach，最后卸载该程序，整个 sockops.c 执行的操作可以通过 load.sh 来完成

也可以在通过 strace ./sockops 来观察加载/attach 具体调用了哪些 OS 提供的 bpf API，并通过 strace 执行 load.sh 里面的命令进行对比

 ## 其它

这只是修改初始拥塞窗口，还有更多任何 socket options 参数都可以通过类似方式来修改。比如接收/发送 buffer：

```
SO_RCVBUF
SO_SNDBUF
SO_MAX_PACING_RATE
SO_PRIORITY
SO_RCVLOWAT
SO_MARK
TCP_CONGESTION
TCP_BPF_IW  //初始拥塞窗口
TCP_BPF_SNDCWND_CLAMP
```

这些值可以在内核里都到其定义：https://github.com/torvalds/linux/blob/v5.10/include/uapi/linux/bpf.h#L4756



## 参考文档

https://arthurchiao.art/blog/bpf-advanced-notes-5-zh/ 
