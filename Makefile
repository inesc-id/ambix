obj-m += ambix.o
ambix-objs := main.o find_kallsyms_lookup_name.o perf_counters.o placement.o tsc.o pid_management.o memory_info.o migrate.o kernel_symbols.o priority_queue.o

KBUILD_CFLAGS += -fno-omit-frame-pointer
CC = gcc
CFLAGS = -Wall -O2

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
	@$(CC) $(CFLAGS) -MD -MF $@ -I/usr/lib/modules/$(shell uname -r)/build/include/ $^
	
insert: ./ambix.ko
	@make -s
	@sudo insmod ./ambix.ko

remove:
	@sudo rmmod ambix

gen_clangd_config:
	@bear -- make

.PHONY: insert remove gen_clangd_config clean
