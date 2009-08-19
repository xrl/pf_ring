#
# (C) 2009 - Luca Deri <deri@ntop.org>
#

obj-m := ring.o

ifeq (,$(BUILD_KERNEL))
BUILD_KERNEL=$(shell uname -r)
endif

# set the install path
INSTDIR := /lib/modules/$(BUILD_KERNEL)/kernel/net/ring

all: Makefile ring.c ring.h
	make -C /lib/modules/$(BUILD_KERNEL)/build SUBDIRS=$(shell pwd) modules

clean:
	make -C /lib/modules/$(BUILD_KERNEL)/build SUBDIRS=$(shell pwd) clean
	\rm -f *~ Module.symvers  Module.markers  modules.order *#

install: all
	mkdir -p $(INSTDIR)
	cp *.ko $(INSTDIR)
