#include <bpf/libbpf.h>
#include <fcntl.h>

#include "tcp_bypass_ops.skel.h"
#include "tcp_bypass.skel.h"

int main(int argc, char **argv)
{
	struct tcp_bypass_ops_bpf *skel;
	struct tcp_bypass_bpf *skel2;
	int err, prog_fd, prog_fd2, cgfd;
	int sock_map_id, sock_map_id2;

	err=0;

	//cgroup mount
	cgfd = open("/tmp/unified", O_RDONLY);
	
	if (cgfd < 0) {
		fprintf(stderr, "ERROR: get cgroup %s fd failed\n", "/tmp/unified/");
		return -1;
	}
	printf("cgfd = %d\n", cgfd);

	//open and load, create ebpf prog and maps
	skel = tcp_bypass_ops_bpf__open_and_load();
	skel2 = tcp_bypass_bpf__open_and_load();
        if (!skel || !skel2) {
                fprintf(stderr, "Failed to open and load BPF skeleton\n");
                return 1;
        }

	fprintf(stdout, "debug attach\n");
	//attach
	bpf_program__attach_cgroup(skel->progs.bpf_sockops_v4, cgfd);	
	
	sock_map_id = bpf_map__fd(skel->maps.sock_ops_map);
	sock_map_id2 = bpf_map__fd(skel2->maps.sock_ops_map);
	//skel2->maps.sock_ops_map=skel->maps.sock_ops_map;
	skel2->maps.sock_ops_map=sock_map_id;

	fprintf(stdout, "debug map %d, %d\n", skel->maps.sock_ops_map, 			skel2->maps.sock_ops_map);
	fprintf(stdout, "debug map id: %d, %d\n", sock_map_id, sock_map_id2);
	
	prog_fd2 = bpf_program__fd(skel2->progs.bpf_tcpip_bypass);

	fprintf(stdout, "debug attach skeleton prog_fd2:%d, map_id:%d\n", prog_fd2, sock_map_id);
	//prog_fd2 = bpf_program__attach_sockmap(prog_fd2, sock_map_id);	
	err = bpf_prog_attach(prog_fd2, sock_map_id, BPF_SK_MSG_VERDICT, 0);
	//prog_fd = tcp_bypass_ops_bpf__attach(skel);
	//prog_fd2 = tcp_bypass_bpf__attach(skel2);
	
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
        tcp_bypass_bpf__destroy(skel2);
        tcp_bypass_ops_bpf__destroy(skel);
        return -err;

}

