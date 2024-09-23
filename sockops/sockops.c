#include <bpf/libbpf.h>
#include <fcntl.h>

#include "sockops.skel.h"

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
	struct sockops_bpf *skel;
	int err, prog_fd, cgfd;

	err=0;
	
	/* Set up libbpf errors and debug info callback */
        libbpf_set_print(libbpf_print_fn);

	//cgroup mount
	cgfd = open("/run/unified", O_RDONLY);
	
	if (cgfd < 0) {
		fprintf(stderr, "ERROR: get cgroup %s fd failed\n", "/run/unified/");
		return -1;
	}
	printf("cgfd = %d\n", cgfd);

	//open and load, create ebpf prog and maps
	skel = sockops_bpf__open_and_load();
        if (!skel) {
                fprintf(stderr, "Failed to open and load BPF skeleton\n");
                return 1;
        }

	fprintf(stdout, "debug attach\n");
	//sockops_bpf__attach(skel);
	//attach
	
	bpf_program__attach_cgroup(skel->progs.bpf_clamp, cgfd);	
	
	prog_fd = bpf_program__fd(skel->progs.bpf_clamp);

	fprintf(stdout, "debug attach skeleton prog_fd:%d, cgfd:%d\n", prog_fd, cgfd);
	err = bpf_prog_attach(prog_fd, 0, BPF_CGROUP_SOCK_OPS, 0);
	
	fprintf(stdout, "end debug attach skeleton\n");
	if (!err) {
        	fprintf(stderr, "Failed to attach bpf prog:%d\n", err);
    		err=-2;
	}

        fprintf(stderr, "sleep\n");
	sleep(10000);

cleanup:
        sockops_bpf__destroy(skel);
        return -err;
}
