#include <linux/swab.h>
#include <bpf/bpf_helpers.h>


/* ebpf helper function
 * The generated function is used for parameter verification
 * by the eBPF verifier
 */
/*
static int BPF_FUNC(msg_redirect_hash, struct sk_msg_md *md,
			void *map, void *key, __u64 flag);
static int BPF_FUNC(sock_hash_update, struct bpf_sock_ops *skops,
			void *map, void *key, __u64 flags);
static void BPF_FUNC(trace_printk, const char *fmt, int fmt_size, ...);
*/

#ifndef __section
#define __section(NAME) 	\
	__attribute__((section(NAME), used))
#endif

#ifndef FORCE_READ
#define FORCE_READ(X) (*(volatile typeof(X)*)&X)
#endif

#ifndef printk
# define printk(fmt, ...)                                      \
    ({                                                         \
        char ____fmt[] = fmt;                                  \
        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
    })
#endif

struct sock_key {
	__u32 sip4;
	__u32 dip4;
	__u8  family;
	__u8  pad1;   // this padding required for 64bit alignment
	__u16 pad2;   // else ebpf kernel verifier rejects loading of the program
	__u32 pad3;
	__u32 sport;
	__u32 dport;
} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
        __uint(max_entries, 65535);
	__type(key, struct sock_key);
	__type(value, int);
} sock_ops_map SEC(".maps");
