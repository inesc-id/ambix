#include <stdio.h>
#include <stdlib.h>
#include "ambix-client.h"

int main(int argc, char **argv) {
    if (argc != 2) {
        return 1;
    }
    int pid = atoi(argv[1]);
    unbind_uds(pid);
    return 0;
}
