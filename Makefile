obj-m += hello.o
#obj-m += perf_counters.o

#obj-m += ambix_impoved.o
#ambix_impoved-objs := hello.o perf_counters.o

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
	
insmod: hello.ko
	@sudo insmod ./hello.ko

rmmod:
	@sudo rmmod hello

run:
	@make -s rmmod || true
	@make -s insmod
	@echo enable > /proc/hello
	@watch cat /proc/hello

.PHONY: insmod rmmod
