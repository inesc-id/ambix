#
# Copyright (c) 2009-2020 Intel Corporation
# written by Roman Dementiev and Jim Harris
#

EXE = pcm-memory.x pcm-power.x

UNAME:=$(shell uname)

CXXFLAGS += -Wall -g -O3 -Wno-unknown-pragmas -std=c++11 -fPIC

# uncomment if your Linux kernel supports access to /dev/mem from user space
# CXXFLAGS += -DPCM_USE_PCI_MM_LINUX

# rely on Linux perf support (user needs CAP_SYS_ADMIN privileges), comment out to disable
ifneq ($(wildcard /usr/include/linux/perf_event.h),)
CXXFLAGS += -DPCM_USE_PERF
endif

ifeq ($(UNAME), Linux)
LIB= -pthread -lrt
CXXFLAGS += -Wextra
OPENSSL_LIB=
# Disabling until we can properly check for dependencies, enable
# yourself if you have the required headers and library installed
#CXXFLAGS += -DUSE_SSL
#OPENSSL_LIB=-lssl -lcrypto -lz -ldl
endif

COMMON_OBJS = msr.o cpucounters.o pci.o mmio.o client_bw.o utils.o topology.o dashboard.o debug.o threadpool.o
EXE_OBJS = $(EXE:.x=.o)
OBJS = $(COMMON_OBJS) $(EXE_OBJS)

# ensure 'make' does not delete the intermediate .o files
.PRECIOUS: $(OBJS)

all: $(EXE) lib

lib: libPCM.a

-include $(OBJS:.o=.d)
libPCM.a: $(COMMON_OBJS)
	ar -rcs $@ $^

%.x: %.o $(COMMON_OBJS)
	$(CXX) $(LDFLAGS) -o $@ $^ $(LIB)

libpcm.so: $(COMMON_OBJS) pcm-core.o
	$(CXX) $(LDFLAGS) $(CXXFLAGS) -DPCM_SILENT -shared $^ $(LIB) -o $@

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $*.cpp -o $*.o
	@# the following lines generate dependency files for the
	@#  target object
	@# from http://scottmcpeak.com/autodepend/autodepend.html
	$(CXX) -MM $(CXXFLAGS) $*.cpp > $*.d
	@# these sed/fmt commands modify the .d file to add a target
	@#  rule for each .h and .cpp file with no dependencies;
	@# this will force 'make' to rebuild any objects that
	@#  depend on a file that has been renamed rather than
	@#  exiting with an error
	@mv -f $*.d $*.d.tmp
	@sed -e 's|.*:|$*.o:|' < $*.d.tmp > $*.d
	@sed -e 's/.*://' -e 's/\\$$//' < $*.d.tmp | fmt -1 | \
	  sed -e 's/^ *//' -e 's/$$/:/' >> $*.d
	@rm -f $*.d.tmp

clean:
	rm -rf *.x *.o *~ *.d *.a *.so
	make -C daemon/daemon/Debug clean
	make -C daemon/client/Debug clean
