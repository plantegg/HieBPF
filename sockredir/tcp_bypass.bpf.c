#include <linux/bpf.h>

#include "tcp_bypass_ops.h"

/* extract the key that identifies the destination socket in the sock_ops_map */
static inline
void sk_msg_extract4_key(struct sk_msg_md *msg,
	struct sock_key *key)
{
	key->sip4 = msg->remote_ip4;
	key->dip4 = msg->local_ip4;
	key->family = 1;

	key->dport = (bpf_htonl(msg->local_port) >> 16);
	key->sport = FORCE_READ(msg->remote_port) >> 16;
	//key->dport = (FORCE_READ(msg->local_port) >> 16);
	//key->sport = (bpf_htonl(msg->remote_port) >> 16);
}

SEC("sk_msg")
int bpf_tcpip_bypass(struct sk_msg_md *msg)
{
    struct  sock_key key = {};
    int ret=0;
    sk_msg_extract4_key(msg, &key);
    //定义在 include/uapi/linux/bpf.h 中,所有内核提供的函数都在这里
    ret=msg_redirect_hash(msg, &sock_ops_map, &key, BPF_F_INGRESS);
    printk("redir msg from %d to %d and ret: %d\n", msg->local_port, 
		(bpf_htonl(msg->remote_port)), ret);
    return SK_PASS;
}

char ____license[] __section("license") = "GPL";
