#
# (C) 2009 - Luca Deri <deri@ntop.org>
#

obj-m := pf_ring.o

ifeq (,$(BUILD_KERNEL))
BUILD_KERNEL=$(shell uname -r)
endif

EXTRA_CFLAGS += -I$(PWD)

HERE=$(PWD)


# set the install path
INSTDIR := /lib/modules/$(BUILD_KERNEL)/kernel/net/pf_ring

all: Makefile pf_ring.c linux/pf_ring.h
	make -C /lib/modules/$(BUILD_KERNEL)/build SUBDIRS=$(HERE) modules

clean:
	make -C /lib/modules/$(BUILD_KERNEL)/build SUBDIRS=$(HERE) clean
	\rm -f *~ Module.symvers  Module.markers  modules.order *#

install:
	mkdir -p $(INSTDIR)
	cp *.ko $(INSTDIR)
	cp linux/pf_ring.h /usr/include/linux
	depmod $(BUILD_KERNEL)
