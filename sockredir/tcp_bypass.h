#include <linux/swab.h>
#include <bpf/bpf_helpers.h>

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
} socks_map SEC(".maps");
