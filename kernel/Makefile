#
# (C) 2009-10 - Luca Deri <deri@ntop.org>
#

obj-m := pf_ring.o

SVNDEF := -DSVN_REV="\"$(shell svnversion -n .)\""

ifeq (,$(BUILD_KERNEL))
BUILD_KERNEL=$(shell uname -r)
endif

EXTRA_CFLAGS += -I$(PWD) $(SVNDEF)

HERE=$(PWD)


# set the install path
INSTDIR := /lib/modules/$(BUILD_KERNEL)/kernel/net/pf_ring

all: Makefile pf_ring.c linux/pf_ring.h
	make -C /lib/modules/$(BUILD_KERNEL)/build SUBDIRS=$(HERE) EXTRA_CFLAGS='$(EXTRA_CFLAGS)' modules

clean:
	make -C /lib/modules/$(BUILD_KERNEL)/build SUBDIRS=$(HERE) clean
	\rm -f *~ Module.symvers  Module.markers  modules.order *#

install:
	mkdir -p $(INSTDIR)
	cp *.ko $(INSTDIR)
	cp linux/pf_ring.h /usr/include/linux
	/sbin/depmod $(BUILD_KERNEL)
