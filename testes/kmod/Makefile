obj-m += test_kmod.o
test_kmod-objs := main.o find_kallsyms_lookup_name.o

KBUILD_CFLAGS += -fno-omit-frame-pointer

.tags:
	@ctags -f $@ -R .

all:
	@make -C ${DEVKERNELROOT}/lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	@make -C ${DEVKERNELROOT}/lib/modules/$(shell uname -r)/build M=$(PWD) clean

help:
	@make -C ${DEVKERNELROOT}/lib/modules/$(shell uname -r)/build help

tags:
	@make -C ${DEVKERNELROOT}/lib/modules/$(shell uname -r)/build M=$(PWD) tags

cscope:
	@make -C ${DEVKERNELROOT}/lib/modules/$(shell uname -r)/build M=$(PWD) cscope

gtags:
	@make -C ${DEVKERNELROOT}/lib/modules/$(shell uname -r)/build M=$(PWD) gtags

%.d: %.c
	@clang -MD -MF $@ -I${DEVKERNELROOT}/usr/lib/modules/$(shell uname -r)/build/include/ $^
	
insmod: all ./test_kmod.ko
	@make -s
	@sudo insmod ./test_kmod.ko

rmmod:
	@sudo rmmod test_kmod

run:
	@make -s rmmod || true
	@make -s insmod
	@watch cat /proc/test_kmod


MEMX_OPT ?= "--no-bind"
run.memx:
	@make -s -C ../memx run NUMACTL='' MEMX='-w 40000 --limit_seconds 30 ${MEMX_OPT}' OMP_NUM_THREADS=8

run.memx.test_kmod:
	@make rmmod || true
	@make insmod
	@make -s run.memx MEMX_OPT="--bind test_kmod"
	@make rmmod || true

# run.memx.test_kmod:
# 	@make -s -C ../test_kmod pcm ambixctl
# 	@make -s run.memx MEMX_OPT="--bind test_kmod"

.PHONY: run.memx.test_kmod run.memx.ambix run.memx

status:
	@sh -c 'if ! pgrep status; then \
		tmux split-window -d "watch -n 1 -- ~/bin/status";   \
		tmux split-window -d "watch cat /proc/test_kmod"; \
		fi'
	@#tmux split-window -d "watch -n 1 -- ~/bin/status"
	@#echo enable > /proc/kmod
	@#tmux split-window -d "watch cat /proc/kmod"


gen_clangd_config:
	@bear -- make

.PHONY: insmod rmmod status run gen_clangd_config
