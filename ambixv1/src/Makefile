CONFIG_MODULE_SIG=n
CC = gcc
CFLAGS = -Wall -lnuma -pthread -lm

MODULE_FILENAME=ambix-mod
obj-m +=  ambix.o
ambix-objs := ambix-mod.o find_kallsyms_lookup_name.o
KO_FILE=$(MODULE_FILENAME).ko

export KROOT=${DEVKERNELROOT}/lib/modules/$(shell uname -r)/build

all: daemon module bind unbind pcm

install: all remove insert

module: ambix-mod.c ambix.h
	@$(MAKE) -C $(KROOT) M=$(PWD) modules -j 12

module_install:
	@$(MAKE) -C $(KROOT) M=$(PWD) modules_install -j 12

clean:
	@$(MAKE) -C $(KROOT) M=$(PWD) clean
	rm -rf   Module.symvers modules.order *.o *.mod socket
	rm ambix-daemon
	rm -rf *.x

insert:
	sudo insmod ./ambix.ko

remove:
	sudo rmmod ambix

force-remove:
	sudo rmmod -f ambix

daemon: ambix-daemon.c ambix.h
	${CC} ${CFLAGS} -o ambix-daemon ambix-daemon.c

client: client.c client_2.c ambix-client.c ambix.h ambix-client.h
	${CC} ${CFLAGS} -o client.o ambix-client.c client.c
	${CC} ${CFLAGS} -o client_2.o ambix-client.c client_2.c

bind: bind.c ambix-client.c ambix-client.h ambix.h
	${CC} ${CFLAGS} -o bind.o ambix-client.c bind.c

unbind: unbind.c ambix-client.c ambix-client.h ambix.h
	${CC} ${CFLAGS} -o unbind.o ambix-client.c unbind.c

pcm: pcm-ambix.h
	cd ./pcm-mod && $(MAKE) -j 32 && mv pcm-memory.x ../
	cd ..