obj-m += kern_move_pages.o
kern_move_pages-objs := mod.c

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
	
insmod: ./kern_move_pages.ko
	@make -s
	@sudo insmod ./kern_move_pages.ko

rmmod:
	@sudo rmmod kern_move_pages

gen_clangd_config:
	@bear -- make

.PHONY: insmod rmmod gen_clangd_config
