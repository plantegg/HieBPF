#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
//#include <linux/if_ether.h> // 提供以太网头定义
//#include <linux/ip.h>       // 提供IP头定义
//#include <linux/icmp.h>     // 提供ICMP头定义
//#include <linux/in.h> //  IPPROTO_ICMP

//#include <bpf/bpf_helpers.h>
//#include <bpf/bpf_endian.h>

#define ETH_P_IP  0x0800 /* Internet Protocol packet    */

struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __type(key, __u32);
        __type(value, long);
        __uint(max_entries, 1);
} cnt SEC(".maps");

//在 event handler 函数内部一般根据传入的唯一 ctx 参数来获得 event 信息
SEC("xdp_drop_count")
int xdp_drop(struct xdp_md *ctx) {
    struct ethhdr *eth = (struct ethhdr *)(long)ctx->data;
    struct iphdr *ip;
    struct icmphdr *icmp;
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    int payload_sz;
    __u32 count_key=0;
    long *count;

    // 确保以太网头部在包内
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // 仅处理IP数据包
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    ip = (struct iphdr *)(eth + 1);
    // 确保IP头部在包内，并检查IP字段
    if ((void *)(ip + 1) > data_end || ip->ihl < 5 || ip->version != 4)
        return XDP_PASS;

    // 仅处理ICMP数据包
    if (ip->protocol != IPPROTO_ICMP)
        return XDP_PASS;

    icmp = (struct icmphdr *)((char *)ip + ip->ihl * 4);
    // 确保ICMP头部在包内
    if ((void *)(icmp + 1) > data_end)
        return XDP_PASS;

    // 计算实际的包内容长度
    payload_sz = data_end - (void *)icmp - sizeof(*icmp);

    if (payload_sz > 100) {
        // 超过100字节则丢弃
        bpf_printk("[DROP] packet size is %d bytes", payload_sz);
	count = bpf_map_lookup_elem(&cnt, &count_key);
	if(count)
	   *count +=1;

        return XDP_DROP;
    } else {
        // 使用 bpf_printk 打印信息到内核日志缓冲区
        bpf_printk("[PASS] packet size is %d bytes", payload_sz);
        return XDP_PASS;
    }
}

char _license[] SEC("license") = "GPL";
