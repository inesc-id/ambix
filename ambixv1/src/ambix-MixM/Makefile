CONFIG_MODULE_SIG=n
CC = gcc
CFLAGS = -Wall -lnuma -pthread -lm

MODULE_FILENAME=ambix_MixM-mod
obj-m +=  $(MODULE_FILENAME).o
KO_FILE=$(MODULE_FILENAME).ko

# export KROOT=/lib/modules/$(shell uname -r)/build
export KROOT=${DEVKERNELROOT}/lib/modules/*/build

all: ctl module bind unbind

module: ambix_MixM-mod.c ambix.h
	@$(MAKE) -C $(KROOT) M=$(PWD) modules -j 12

module_install:
	@$(MAKE) -C $(KROOT) M=$(PWD) modules_install -j 12

clean:
	@$(MAKE) -C $(KROOT) M=$(PWD) clean
	rm -rf   Module.symvers modules.order *.o *.mod socket
	rm -rf *.x

insert:
	sudo insmod $(KO_FILE)

remove:
	sudo rmmod $(MODULE_FILENAME)

force-remove:
	sudo rmmod -f $(MODULE_FILENAME)

%.d: %.c
	@clang -MD -MF $@ -I${DEVKERNELROOT}/usr/lib/modules/*/build/include/ $^

ctl: ambix_MixM-ctl.c ambix.h
	${CC} ${CFLAGS} -o ambix_MixM-ctl.o ambix_MixM-ctl.c

client: client.c client_2.c ambix-client.c ambix.h ambix-client.h
	${CC} ${CFLAGS} -o client.o ambix-client.c client.c
	${CC} ${CFLAGS} -o client_2.o ambix-client.c client_2.c

bind: bind.c ambix-client.c ambix-client.h ambix.h
	${CC} ${CFLAGS} -o bind.o ambix-client.c bind.c

unbind: unbind.c ambix-client.c ambix-client.h ambix.h
	${CC} ${CFLAGS} -o unbind.o ambix-client.c unbind.c
