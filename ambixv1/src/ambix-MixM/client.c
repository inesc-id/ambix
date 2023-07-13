#include <stdio.h>
#include <stdlib.h>
#include "ambix-client.h"

#include <unistd.h>


int main() {
    int pid = getpid();
    if(!bind_uds(pid)) {
        return 1;
    }
    printf("BIND OK\n");

    int *a = malloc(sizeof(int) * 90000000);

    for(int i=0; i<90000000; i++) {
        a[i] = 1;
    }

    getchar();

    printf("%d\n", a[0]);

    if(!unbind_uds(pid)) {
        return 1;
    }

    getchar();

    printf("UNBIND OK\n");
    return 0;
}
