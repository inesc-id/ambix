obj-m += kmod.o
kmod-objs := main.o find_kallsyms_lookup_name.o perf_counters.o placement.o

KBUILD_CFLAGS += -fno-omit-frame-pointer
export DEBUG = YES

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
	
insmod: ./kmod.ko
	@make -s
	@sudo insmod ./kmod.ko

rmmod:
	@sudo rmmod kmod

run:
	@make -s rmmod || true
	@make -s insmod
	@echo enable > /proc/kmod
	@watch cat /proc/kmod


MEMX_OPT ?= "--no-bind"
run.memx:
	@make -s -C ../memx run NUMACTL='' MEMX='-w 40000 --limit_seconds 30 ${MEMX_OPT}' OMP_NUM_THREADS=8

run.memx.kmod:
	@make rmmod || true
	@make insmod
	@echo enable > /proc/kmod
	@make -s run.memx MEMX_OPT="--bind kmod"
	@make rmmod || true

run.memx.ambix:
	@make -s -C ../ambix pcm ambixctl
	@make -s run.memx MEMX_OPT="--bind ambix"

.PHONY: run.memx.kmod run.memx.ambix run.memx

status:
	@sh -c 'if ! pgrep status; then \
		tmux split-window -d "watch -n 1 -- ~/bin/status";   \
		tmux split-window -d "watch cat /proc/kmod"; \
		fi'
	@#tmux split-window -d "watch -n 1 -- ~/bin/status"
	@#echo enable > /proc/kmod
	@#tmux split-window -d "watch cat /proc/kmod"


.PHONY: insmod rmmod status run
