#include <bpf/libbpf.h>
#include <fcntl.h>

#include "tcp_bypass.skel.h"

#define BYPASS_DEBUG

#ifdef BYPASS_DEBUG
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
        return vfprintf(stderr, format, args);
}
#else
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
        return 0;
}
#endif


int main(int argc, char **argv)
{
	struct tcp_bypass_bpf *skel;
	int err, prog_fd, cgfd;
	int sock_map_id;

	err=0;
	
	/* Set up libbpf errors and debug info callback */
        libbpf_set_print(libbpf_print_fn);

	//cgroup mount
	cgfd = open("/tmp/unified", O_RDONLY);
	
	if (cgfd < 0) {
		fprintf(stderr, "ERROR: get cgroup %s fd failed\n", "/tmp/unified/");
		return -1;
	}
	printf("cgfd = %d\n", cgfd);

	//open and load, create ebpf prog and maps
	skel = tcp_bypass_bpf__open_and_load();
        if (!skel) {
                fprintf(stderr, "Failed to open and load BPF skeleton\n");
                return 1;
        }

	fprintf(stdout, "debug attach\n");
	//attach
	bpf_program__attach_cgroup(skel->progs.sockops_v4, cgfd);	
	
	sock_map_id = bpf_map__fd(skel->maps.socks_map);

	fprintf(stdout, "debug map id: %d\n", sock_map_id);
	
	prog_fd = bpf_program__fd(skel->progs.tcp_bypass);

	fprintf(stdout, "debug attach skeleton prog_fd:%d, map_id:%d\n", prog_fd, sock_map_id);
	err = bpf_prog_attach(prog_fd, sock_map_id, BPF_SK_MSG_VERDICT, 0);
	
	fprintf(stdout, "end debug attach skeleton\n");
	if (!prog_fd) {
        	fprintf(stderr, "Failed to attach FD\n");
    		err=-1;
	}
	if (!err) {
        	fprintf(stderr, "Failed to attach FD2:%d\n", err);
    		err=-2;
	}
	
        fprintf(stderr, "sleep\n");
	sleep(10000);

cleanup:
        tcp_bypass_bpf__destroy(skel);
        return -err;
}
