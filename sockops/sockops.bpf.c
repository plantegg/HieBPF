#include <linux/bpf.h>
#include <linux/ip.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef AF_INET6
#define AF_INET6 10
#endif

#ifndef printk
# define printk(fmt, ...)                                      \
    ({                                                         \
        char ____fmt[] = fmt;                                  \
        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
    })
#endif

SEC("sockops")
int bpf_clamp(struct bpf_sock_ops *skops) {
    int bufsize = 123456;
    int to_init = 99;
    int clamp = 999;
    int rv = 0;

    printk("change socket options");
    
    /* Check that both hosts are within same datacenter. For
     * this example it is the case when the first 5.5 bytes of
     * their IPv6 addresses are the same.
     */
    if (skops->family == AF_INET){
        switch (skops->op) {
        case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
            rv = bpf_setsockopt(skops, SOL_TCP, TCP_BPF_SNDCWND_CLAMP, &clamp, sizeof(clamp));
            break;
        case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
            /* Set cwnd clamp and sndbuf, rcvbuf of passive connections */
            /* See actual program for this code */
	    //bpf_setsockopt 是内核在 ./include/uapi/linux/bpf.h 提供的bpf helper 函数
	    //第三个参数 TCP_BPF_IW 对应这次要修改的哪个 options 
	    rv = bpf_setsockopt(skops, SOL_TCP, TCP_BPF_IW, &to_init, sizeof(to_init));
	    printk("change init cwnd: %d\n", to_init);
        case BPF_SOCK_OPS_TIMEOUT_INIT:
            rv = 0;
            break;
        case BPF_SOCK_OPS_TCP_CONNECT_CB: /* Set sndbuf and rcvbuf of active connections */
            rv = bpf_setsockopt(skops, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
            rv = rv + bpf_setsockopt(skops, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
	    printk("change buffer: %d\n", bufsize);
            break;
        default:
            rv = -1;
        }
    } else {
        rv = -1;
    }

    skops->reply = rv;
    return 1;
}

char _license[] SEC("license") = "GPL";
