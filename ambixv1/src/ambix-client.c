#include "ambix.h"

#include <numa.h>
#include <numaif.h>

#include <stdio.h>
#include <stdlib.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>

#include <errno.h>
#include <unistd.h>


int bind_uds(int pid_arg) {
    // Unix domain socket
    struct sockaddr_un uds_addr;
    int unix_fd, w_ret;
    req_t bind_req;
    int pid;

    if (pid_arg == 0) {
        pid = getpid();
    }
    else {
        pid = pid_arg;
    }

    // Keep process pages in primary memory (disables swapping for pages in a set of addresses)
    // False-positive implicit function declaration on mlock2()
    // #pragma GCC diagnostic push
    // #pragma GCC diagnostic ignored "-Wimplicit-function-declaration"
    // if(mlock2(0, MAX_ADDRESS, MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT)) {
    //     fprintf(stderr, "Error in mlock: %s\n", strerror(errno)); // Update /etc/security/limits.conf
    //     return 0;
    // }
    // #pragma GCC diagnostic pop

    /*struct bitmask *bm;
    int ncpus = numa_num_configured_cpus();
    bm = numa_bitmask_alloc(ncpus);

    for(int i=0; i<n_dram_nodes; i++) {
        numa_bitmask_setbit(bm, DRAM_NODES[i]);
    }
    for(int i=0; i<n_nvram_nodes; i++) {
        numa_bitmask_setbit(bm, NVRAM_NODES[i]);
    }

    if(set_mempolicy(MPOL_BIND, bm->maskp, bm->size + 1)) {
        fprintf(stderr, "Error in set_mempolicy: %s\n", strerror(errno));
        return 0;
    }*/

    if((unix_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        fprintf(stderr, "Error creating UD socket: %s\n", strerror(errno));
        return 0;
    }
    memset(&uds_addr, 0, sizeof(uds_addr));
    uds_addr.sun_family = AF_UNIX;

    strncpy(uds_addr.sun_path, UDS_path, sizeof(uds_addr.sun_path)-1);

    if(connect(unix_fd, (struct sockaddr*)&uds_addr, sizeof(uds_addr))) {
        fprintf(stderr, "Error connecting to server via UDS: %s\n", strerror(errno));

        close(unix_fd);
        return 0;
    }

    bind_req.op_code = BIND_OP;
    bind_req.pid_n = pid;

    if ((w_ret = write(unix_fd, &bind_req, sizeof(bind_req))) != sizeof(bind_req)) {
        if (w_ret == -1) {
            fprintf(stderr, "Error writing to UDS fd: %s\n", strerror(errno));
        }
        else {
            fprintf(stderr, "Unexpected amount of bytes written to UDS fd.\n");
        }

        close(unix_fd);
        return 0;
    }

    close(unix_fd);
    return 1;
}


int unbind_uds(int pid_arg) {
    // Unix domain socket
    struct sockaddr_un uds_addr;
    int unix_fd, w_ret;
    req_t unbind_req;
    int pid;

    if (pid_arg == 0) {
        pid = getpid();
    }
    else {
        pid = pid_arg;
    }
    // munlock(0, MAX_ADDRESS);

    if((unix_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        fprintf(stderr, "Error creating UD socket: %s\n", strerror(errno));
        return 0;
    }
    memset(&uds_addr, 0, sizeof(uds_addr));
    uds_addr.sun_family = AF_UNIX;

    strncpy(uds_addr.sun_path, UDS_path, sizeof(uds_addr.sun_path)-1);

    if(connect(unix_fd, (struct sockaddr*)&uds_addr, sizeof(uds_addr))) {
        fprintf(stderr, "Error connecting to server via UDS: %s\n", strerror(errno));

        close(unix_fd);
        return 0;
    }

    unbind_req.op_code = UNBIND_OP;
    unbind_req.pid_n = pid;

    if ((w_ret = write(unix_fd, &unbind_req, sizeof(unbind_req))) != sizeof(unbind_req)) {
        if (w_ret == -1) {
            fprintf(stderr, "Error writing to UDS fd: %s\n", strerror(errno));
        }
        else {
            fprintf(stderr, "Unexpected amount of bytes written to UDS fd.\n");
        }


        close(unix_fd);
        return 0;
    }

    close(unix_fd);
    return 1;
}

void bind_uds_ft_() {
    bind_uds(0);
}
void unbind_uds_ft_() {
    unbind_uds(0);
}
