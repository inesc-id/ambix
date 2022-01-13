obj-m += mplace.o
mplace-objs := main.o find_kallsyms_lookup_name.o perf_counters.o placement.o

export DEBUG = YES
#export CONFIG_DYNAMIC_DEBUG ?= YES

.tags:
	@ctags -f $@ -R .

all:
	@make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	@make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

help:
	@make -C /lib/modules/$(shell uname -r)/build help

tags:
	@make -C /lib/modules/$(shell uname -r)/build M=$(PWD) tags

cscope:
	@make -C /lib/modules/$(shell uname -r)/build M=$(PWD) cscope

gtags:
	@make -C /lib/modules/$(shell uname -r)/build M=$(PWD) gtags

%.d: %.c
	@clang -MD -MF $@ -I/usr/lib/modules/$(shell uname -r)/build/include/ $^
	
insmod: ./mplace.ko
	@sudo insmod ./mplace.ko

rmmod:
	@sudo rmmod mplace

run:
	@make -s rmmod || true
	@make -s insmod
	@echo enable > /proc/mplace
	@watch cat /proc/mplace

run.all:
	@make -s
	@make -s insmod  || /bin/true
	@make -s -C ../memx run NUMACTL='-m1'
	@make -s rmmod  || /bin/true

.PHONY: insmod rmmod
