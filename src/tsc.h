#ifndef __TSC_H__
#define __TSC_H__

inline u64 tsc_rd(void);

void tsc_init(void);

u64 tsc_to_msec(u64 tsc);
u64 tsc_to_usec(u64 tsc);
u64 tsc_to_nsec(u64 tsc);
u64 tsc_from_usec(u64 usec);
#endif
