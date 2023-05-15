obj-m += ambix.o
ambix-objs := main.o find_kallsyms_lookup_name.o perf_counters.o placement.o tsc.o

KBUILD_CFLAGS += -fno-omit-frame-pointer
export DEBUG = YES

.tags:
	@ctags -f $@ -R .

all:
ifeq ($(shell hostname),chord)
	@make -C ${DEVKERNELROOT}/lib/modules/*/build M=$(PWD) modules
else
	@make -C ${DEVKERNELROOT}/lib/modules/$(shell uname -r)/build M=$(PWD) modules
endif

clean:
ifeq ($(shell hostname),chord)
	@make -C ${DEVKERNELROOT}/lib/modules/*/build M=$(PWD) clean
else
	@make -C ${DEVKERNELROOT}/lib/modules/$(shell uname -r)/build M=$(PWD) clean
endif

help:
ifeq ($(shell hostname),chord)
	@make -C ${DEVKERNELROOT}/lib/modules/*/build help
else
	@make -C ${DEVKERNELROOT}/lib/modules/$(shell uname -r)/build help
endif

tags:
ifeq ($(shell hostname),chord)
	@make -C ${DEVKERNELROOT}/lib/modules/*/build M=$(PWD) tags
else
	@make -C ${DEVKERNELROOT}/lib/modules/$(shell uname -r)/build M=$(PWD) tags
endif

cscope:
ifeq ($(shell hostname),chord)
	@make -C ${DEVKERNELROOT}/lib/modules/*/build M=$(PWD) cscope
else
	@make -C ${DEVKERNELROOT}/lib/modules/$(shell uname -r)/build M=$(PWD) cscope
endif

gtags:
ifeq ($(shell hostname),chord)
	@make -C ${DEVKERNELROOT}/lib/modules/*/build M=$(PWD) gtags
else
	@make -C ${DEVKERNELROOT}/lib/modules/$(shell uname -r)/build M=$(PWD) gtags
endif

%.d: %.c
ifeq ($(shell hostname),chord)
	@clang -MD -MF $@ -I${DEVKERNELROOT}/usr/lib/modules/*/build/include/ $^
else
	@clang -MD -MF $@ -I${DEVKERNELROOT}/usr/lib/modules/$(shell uname -r)/build/include/ $^
endif
	
insmod: ./ambix.ko
	@make -s
	@sudo insmod ./ambix.ko

rmmod:
	@sudo rmmod ambix

run:
	@make -s rmmod || true
	@make -s insmod
	@watch cat /proc/ambix


MEMX_OPT ?= "--no-bind"
run.memx:
	@make -s -C ../memx run NUMACTL='' MEMX='-w 40000 --limit_seconds 30 ${MEMX_OPT}' OMP_NUM_THREADS=8

run.memx.ambix:
	@make rmmod || true
	@make insmod
	@make -s run.memx MEMX_OPT="--bind ambix"
	@make rmmod || true

# run.memx.ambix:
# 	@make -s -C ../ambix pcm ambixctl
# 	@make -s run.memx MEMX_OPT="--bind ambix"

.PHONY: run.memx.ambix run.memx.ambix run.memx

status:
	@sh -c 'if ! pgrep status; then \
		tmux split-window -d "watch -n 1 -- ~/bin/status";   \
		tmux split-window -d "watch cat /proc/ambix"; \
		fi'
	@#tmux split-window -d "watch -n 1 -- ~/bin/status"
	@#echo enable > /proc/kmod
	@#tmux split-window -d "watch cat /proc/kmod"


gen_clangd_config:
	@bear --verbose -- make

.PHONY: insmod rmmod status run gen_clangd_config
