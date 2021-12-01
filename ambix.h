#pragma once

// Intervals and limits:

#define MEMCHECK_INTERVAL PCM_DELAY * 1000
#define NVRAMWRCHK_INTERVAL PCM_DELAY * 1000
#define CLEAR_DELAY 50

// BW info (for checking pcm output)
#define DRAM_BW_MAX 50000
#define NVRAM_BW_MAX 20000

// PID info
#define MAX_PIDS 500 // sets the number of PIDs that can be bound to Ambix at any given time
#define MAX_PID_N 2147483647 // set to INT_MAX. true max pid number is shown in /proc/sys/kernel/pid_max

// Find-related constants:
#define DRAM_MODE 0
#define NVRAM_MODE 1
#define NVRAM_INTENSIVE_MODE 2
#define SWITCH_MODE 3
#define NVRAM_CLEAR 4
#define NVRAM_WRITE_MODE 5
//#define MAX_N_FIND 131071U
//##define MAX_N_FIND 512U*1024*1024

// Netlink:
#define NETLINK_USER 31
#define MAX_PAYLOAD 4096 // Theoretical max is 32KB - netlink header - padding but limiting payload to 4096 or page size is standard in kernel programming
#define MAX_PACKETS 512
#define MAX_N_PER_PACKET (MAX_PAYLOAD/sizeof(addr_info_t)) // Currently 1MB of pages


// Unix Domain Socket:
#define UDS_path "./socket"
#define MAX_BACKLOG 5

// Comm-related OP codes:
#define FIND_OP 0
#define BIND_OP 1
#define UNBIND_OP 2

// Comm-related structures:
typedef struct req {
    int op_code;
    int pid_n; // Stores pid for BIND/UNBIND and the number of pages for FIND
    int mode;
} req_t;

//Client-ctl comms:
#define PORT 8080
#define SELECT_TIMEOUT 1

// Misc:
#define MAX_COMMAND_SIZE 80
#define MAX_INTERVAL_MUL 1
#define INTERVAL_INC_FACTOR 1

// Memory ranges: (64-bit systems only use 48-bit)
#define IS_64BIT (sizeof(void*) == 8)
#define MAX_ADDRESS (IS_64BIT ? 0xFFFF880000000000UL : 0xC0000000UL) // Max user-space addresses for the x86 architecture
#define MAX_ADDRESS_ARM (IS_64BIT ? 0x800000000000UL : 0xC0000000UL) // Max user-space addresses for the ARM architecture


// Helper functions:

#define BETWEEN(value, min, max) (value <= max && value >= min)

int int_min(int val1, int val2) {
    if (val1 > val2) {
        return val2;
    }
    return val1;
}

