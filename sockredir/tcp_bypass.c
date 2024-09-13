#include <bpf/libbpf.h>
#include <fcntl.h>

#include "tcp_bypass.skel.h"

int main(int argc, char **argv)
{
	struct tcp_bypass_bpf *skel;
	int err, prog_fd, cgfd;
	int sock_map_id;

	err=0;

	//cgroup mount
	cgfd = open("/tmp/unified", O_RDONLY);
	
	if (cgfd < 0) {
		fprintf(stderr, "ERROR: get cgroup %s fd failed\n", "/tmp/unified/");
		return -1;
	}

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

	prog_fd = bpf_program__fd(skel->progs.tcp_bypass);
	err = bpf_prog_attach(prog_fd, sock_map_id, BPF_SK_MSG_VERDICT, 0);
	
	if (err) {
        	fprintf(stderr, "Failed to attach FD2:%d\n", err);
    		err=-2;
		goto cleanup;
	}
	fprintf(stdout, "tcp bypass bpf is running\n");	
	sleep(10000);

cleanup:
        tcp_bypass_bpf__destroy(skel);
        return err;
}
