#!/usr/bin/make
#
# Makefile for building Linux Broadcom Gigabit ethernet driver as a module.
#

KVER=
ifeq ($(KVER),)
	KVER=$(shell uname -r)
endif

BCMCFGDIR=
BCMSRCDIR=

ifeq ($(BCMCFGDIR),)
	ifeq ($(shell ls /lib/modules/$(KVER)/build > /dev/null 2>&1 && echo build),)
		ifneq ($(shell ls /usr/src/linux > /dev/null 2>&1 && echo linux),)
			BCMCFGDIR=/usr/src/linux
		endif
	else
		BCMCFGDIR=/lib/modules/$(KVER)/build
		ifneq ($(shell ls /lib/modules/$(KVER)/source > /dev/null 2>&1 && echo source),)
			BCMSRCDIR=/lib/modules/$(KVER)/source
		endif
	endif
endif

ifeq ($(BCMSRCDIR),)
	BCMSRCDIR=$(BCMCFGDIR)
endif

ifeq ($(BCMCFGDIR),)
	$(error Linux kernel config directory not found)
endif

# PREFIX may be set by the RPM build to set the effective root.
PREFIX=

ifeq ($(BCMMODDIR),)
	ifeq ($(shell ls /lib/modules/$(KVER)/updates > /dev/null 2>&1 && echo 1),1)
		BCMMODDIR=/lib/modules/$(KVER)/updates
	else
		ifeq ($(shell grep -q "search.*[[:space:]]updates" /etc/depmod.conf > /dev/null 2>&1 && echo 1),1)
			BCMMODDIR=/lib/modules/$(KVER)/updates
		else
			ifeq ($(shell grep -q "search.*[[:space:]]updates" /etc/depmod.d/* > /dev/null 2>&1 && echo 1),1)
				BCMMODDIR=/lib/modules/$(KVER)/updates
			else
				BCMMODDIR=/lib/modules/$(KVER)/kernel/drivers/net
			endif
		endif
	endif
endif

ifeq ($(shell [ -e /etc/SuSE-release ] && echo 1),1)
	SUSEVERS = $(shell grep VERSION /etc/SuSE-release | sed -e 's/.*= //')
else
	SUSEVERS = 0
endif

# check if 2.4 kernel or 2.5+ kernel
BCM_KVER := $(shell echo $(KVER) | cut -c1-3 | sed 's/2\.[56]/2\.6/')

ifeq ($(BCM_KVER), 2.6)
# Makefile for 2.5+ kernel

BCM_DRV = tg3.ko

ifneq ($(KERNELRELEASE),)

obj-m += tg3.o

else

default: tg3_flags.h supported_file
	make -C $(BCMCFGDIR) SUBDIRS=$(shell pwd) modules

endif

else # ifeq ($(BCM_KVER),2.6)
# Makefile for 2.4 kernel

BCM_DRV = tg3.o

CC = gcc

CFLAGS=-DMODULE -D__KERNEL__ -Wall -Wstrict-prototypes -I$(BCMCFGDIR)/include -fno-strict-aliasing

ifeq ($(shell grep netif_poll_disable $(BCMSRCDIR)/include/linux/netdevice.h > /dev/null 2>&1 && echo newnetif),)
  CFLAGS+=-DOLD_NETIF
endif

ARCH:=$(shell uname -m)

ifeq ($(ARCH),x86_64)
  CFLAGS+=-mno-red-zone -mcmodel=kernel -pipe -finline-limit=2000
endif

ifeq ($(ARCH),ia64)
  CFLAGS+=-pipe -ffixed-r13 -mfixed-range=f10-f15,f32-f127 -falign-functions=32
endif

ifeq ($(ARCH),ppc64)
  ifneq ($(shell ls /opt/cross/bin/powerpc64-linux-gcc > /dev/null 2>&1 && echo ppcgcc),)
    CC=/opt/cross/bin/powerpc64-linux-gcc
  endif

  CFLAGS+=-fno-common -fomit-frame-pointer -msoft-float -pipe -mminimal-toc -fno-builtin
endif

CFLAGS += -O2

all: tg3_flags.h supported_file tg3.o

endif # ifeq ($(BCM_KVER),2.6)

tg3_flags.h:
	sh makeflags.sh $(BCMSRCDIR) > tg3_flags.h

tg3.4.gz:
	gzip -c tg3.4 > tg3.4.gz


ifeq ($(BCM_KVER), 2.6)
install: default tg3.4.gz
else
install: $(BCM_DRV) tg3.4.gz
endif
	mkdir -p $(PREFIX)/$(BCMMODDIR);
	install -m 444 $(BCM_DRV) $(PREFIX)/$(BCMMODDIR);
	@if [ "$(PREFIX)" = "" ]; then /sbin/depmod -a ;\
	else echo " *** Run '/sbin/depmod -a' to update the module database.";\
	fi
	install -m 444 tg3.4.gz $(PREFIX)/usr/share/man/man4;\

.PHONEY: all supported_file clean install

supported_file:
	@if [ $(SUSEVERS) -ge 11 ]; then \
		echo "tg3.ko external" > Module.supported; \
	fi

clean:
	-rm -f tg3.o tg3.ko tg3.mod.c tg3.mod.o tg3.4.gz tg3_flags.h .tg3* Module.symvers modules.order
	-rm -rf .tmp_versions Module.supported

