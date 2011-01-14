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
INSTDIR := $(DESTDIR)/lib/modules/$(BUILD_KERNEL)/kernel/net/pf_ring

all: Makefile pf_ring.c linux/pf_ring.h
	@if test "$(USER)" = "root"; then \
		echo "********** WARNING WARNING WARNING **********"; \
		echo "*"; \
		echo "* Compiling PF_RING as root might lead you to compile errors"; \
		echo "* Please compile PF_RING as unpriviliged user"; \
		echo "*"; \
		echo "*********************************************"; \
	fi
	make -C /lib/modules/$(BUILD_KERNEL)/build SUBDIRS=$(HERE) EXTRA_CFLAGS='$(EXTRA_CFLAGS)' modules

clean:
	make -C /lib/modules/$(BUILD_KERNEL)/build SUBDIRS=$(HERE) clean
	\rm -f *~ Module.symvers  Module.markers  modules.order *#

install:
	mkdir -p $(INSTDIR)
	cp *.ko $(INSTDIR)
	cp linux/pf_ring.h $(DESTDIR)/usr/include/linux
	cp linux/pf_ring.h /usr/src/$(uname -r)/include/linux/
ifeq (,$(DESTDIR))
	/sbin/depmod $(BUILD_KERNEL)
endif
