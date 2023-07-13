#ifndef _PCM_AMBIX_H
#define _PCM_AMBIX_H

#define MAX_SOCKETS 2
#define PCM_FILE_NAME "memdata"
#define PCM_DELAY 1
#define PMM_MIXED 1

#include <stdint.h>

typedef struct memdata {
    float sys_dramReads, sys_dramWrites;
    float sys_pmmReads, sys_pmmWrites;
    float sys_pmmAppBW, sys_pmmMemBW;
    uint64_t total_rDram, total_wDram, total_rOptane, total_wOptane;
} memdata_t;


#endif
