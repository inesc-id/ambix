#include <stdio.h>
#include <stdlib.h>
#include "ambix-client.h"
#include <unistd.h>


int main() {
    int array_size = 500000000;
    int pid = getpid();
    if(!bind_uds(pid)) {
        return 1;
    }
    printf("BIND OK\n");

    int *a = malloc(sizeof(int) * array_size);

    while(1) {
        char c = getchar();
        if(c == 'a') {
            for(int i=0; i<array_size; i++) {
                a[i] = 1;
            }
        }
        else if(c == 'b') {
            for(int i=0; i<array_size/2; i++) {
                a[i] = 1;
            }
        }
        else if(c == 'c') {
            for(int i=array_size/2; i<array_size; i++) {
                a[i] = 1;
            }
        }
        else if(c == 'd') {
            for(int i=0; i<300 && i < array_size; i++) {
                a[i] = 1;
            }
        }

        else if(c == 'e') {
            for(int i=array_size; i>array_size-300 && i>0; i--) {
                a[i] = 1;
            }
        }
        else if(c == 'f') {
            printf("Exiting.\n");
            break;
        }
        else if(c == 'r') {
            int tmp;
            for(int i=0; i<array_size; i++) {
                tmp = a[i];
            }
        }
    }

    if(!unbind_uds(pid)) {
        return 1;
    }

    printf("UNBIND OK\n");
    return 0;
}
