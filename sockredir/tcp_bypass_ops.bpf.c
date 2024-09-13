#include <linux/bpf.h>

#include "tcp_bypass_ops.h"


/*
 * extract the key identifying the socket source of the TCP event 
 */
static inline
void sk_extractv4_key(struct bpf_sock_ops *ops,
	struct sock_key *key)
{
	// keep ip and port in network byte order
	key->dip4 = ops->remote_ip4;
	key->sip4 = ops->local_ip4;
	key->family = 1;
	
	// local_port is in host byte order, and 
	// remote_port is in network byte order
	key->sport = (bpf_htonl(ops->local_port) >> 16);
	key->dport = FORCE_READ(ops->remote_port) >> 16;
}

static inline
void bpf_sock_ops_ipv4(struct bpf_sock_ops *skops)
{
	struct sock_key key = {};

	//skip port 10000, 10000端口作为正常流量进行对比
	if(bpf_ntohl(skops->remote_port)==10000 || skops->local_port==10000)
		return ;
	
	sk_extractv4_key(skops, &key);

	// insert the source socket in the sock_ops_map
	//定义在 include/uapi/linux/bpf.h 中,OS 提供的能力
	//bpf.h 种的函数被libbpf 重新在 bpf_helper_defs.h 中封装
	int ret = sock_hash_update(skops, &sock_ops_map, &key, BPF_NOEXIST);
	printk("<<< ipv4 op = %d, port %d --> %d\n", 
		skops->op, skops->local_port, bpf_ntohl(skops->remote_port));
	if (ret != 0) {
		printk("FAILED: sock_hash_update ret: %d\n", ret);
	}
}

SEC("sockops")
int bpf_sockops_v4(struct bpf_sock_ops *skops)
{
	switch (skops->op) {
        case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
        case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
		if (skops->family == 2) { //AF_INET
                        bpf_sock_ops_ipv4(skops);
		}
                break;
        default:
                break;
        }
	return 0;
}

char ____license[] __section("license") = "GPL";
int _version __section("version") = 1;