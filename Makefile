obj-m += kmod.o
kmod-objs := hello.o find_kallsyms_lookup_name.o perf_counters.o ambix_hyb.o

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
	
insmod: kmod.ko
	@sudo insmod ./kmod.ko

rmmod:
	@sudo rmmod kmod

run:
	@make -s rmmod || true
	@make -s insmod
	@echo enable > /proc/hello
	@watch cat /proc/hello

.PHONY: insmod rmmod
