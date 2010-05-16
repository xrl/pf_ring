#!/usr/bin/make
# Makefile for building Linux Broadcom Gigabit ethernet driver as a module.
# $id$
KVER=
ifeq ($(KVER),)
  KVER=$(shell uname -r)
endif

# PREFIX may be set by the RPM build to set the effective root.
PREFIX=
ifeq ($(shell ls /lib/modules/$(KVER)/build > /dev/null 2>&1 && echo build),)
# SuSE source RPMs
  _KVER=$(shell echo $(KVER) | cut -d "-" -f1,2)
  _KFLA=$(shell echo $(KVER) | cut -d "-" -f3)
  _ARCH=$(shell file -b /lib/modules/$(shell uname -r)/build | cut -d "/" -f5)
  ifeq ($(_ARCH),)
    _ARCH=$(shell uname -m)
  endif
  ifeq ($(shell ls /usr/src/linux-$(_KVER)-obj > /dev/null 2>&1 && echo linux),)
    LINUX=
  else
    LINUX=/usr/src/linux-$(_KVER)-obj/$(_ARCH)/$(_KFLA)
    LINUXSRC=/usr/src/linux-$(_KVER)
  endif
else
  LINUX=/lib/modules/$(KVER)/build
  ifeq ($(shell ls /lib/modules/$(KVER)/source > /dev/null 2>&1 && echo source),)
    LINUXSRC=$(LINUX)
  else
    LINUXSRC=/lib/modules/$(KVER)/source
  endif
endif

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

ifneq ($(shell grep netdump_mode $(LINUXSRC)/include/linux/kernel.h > /dev/null 2>&1 && echo rh),)
  NETDUMP_CFLAG = -DRED_HAT_LINUX_KERNEL
else
  NETDUMP_CFLAG =
endif

ifeq ($(shell ls $(LINUXSRC)/include/net/netevent.h > /dev/null 2>&1 && echo ne),)
  NETEVENT_CFLAG =
else
  NETEVENT_CFLAG = -DHAVE_NETEVENT
endif

ifneq ($(shell grep skb_transport_offset $(LINUXSRC)/include/linux/skbuff.h > /dev/null 2>&1 && echo sk),)
  SKB_CFLAG = -DNEW_SKB
else
  SKB_CFLAG =
endif

ifneq ($(shell grep "static inline struct iphdr \*ip_hdr" $(LINUXSRC)/include/linux/ip.h > /dev/null 2>&1 && echo ip),)
  IP_CFLAG = -DHAVE_IP_HDR
else
  IP_CFLAG =
endif

ifneq ($(shell grep "__le32" $(LINUXSRC)/include/linux/types.h > /dev/null 2>&1 && echo le32),)
  LE32_CFLAG = -DHAVE_LE32
else
  LE32_CFLAG =
endif

ifneq ($(shell grep "bool" $(LINUXSRC)/include/linux/types.h > /dev/null 2>&1 && echo bool),)
  BOOL_CFLAG = -DHAVE_BOOL
else
  BOOL_CFLAG =
endif

# check if 2.4 kernel or 2.5+ kernel
BCM_KVER:=$(shell echo $(KVER) | cut -c1-3 | sed 's/2\.[56]/2\.6/')
BCM_CNIC:=0

ifeq ($(BCM_KVER), 2.6)
# Makefile for 2.5+ kernel
BCM_CNIC:=$(shell echo $(KVER) | cut -c5- | cut -d. -f1 | cut -d- -f1 | \
	awk '{ if ($$1 > 15) print "1"; else print "0"}')

ifeq ($(BCM_CNIC), 1)
BCM_DRV = bnx2.ko cnic.ko
else
BCM_DRV = bnx2.ko
endif

ifneq ($(KERNELRELEASE),)

obj-m += bnx2.o
ifeq ($(BCM_CNIC), 1)
obj-m += cnic.o
endif

EXTRA_CFLAGS = $(NETDUMP_CFLAG) $(NETEVENT_CFLAG) $(SKB_CFLAG) $(IP_CFLAG) $(LE32_CFLAG) $(BOOL_CFLAG)

else

default: support_file
	make -C $(LINUX) SUBDIRS=$(shell pwd) modules

endif

else # ifeq ($(BCM_KVER),2.6)
# Makefile for 2.4 kernel

BCM_DRV = bnx2.o

ifeq ($(LINUX),)
  $(error Linux kernel source tree not found)
endif

CC = gcc

CFLAGS=-DMODULE -D__KERNEL__ -Wall -Wstrict-prototypes -I$(LINUX)/include $(NETDUMP_CFLAG)

ifeq ($(shell grep netif_poll_disable $(LINUXSRC)/include/linux/netdevice.h > /dev/null 2>&1 && echo newnetif),)
  CFLAGS+=-DOLD_NETIF
endif

ifeq ($(wildcard ~/rpmdir),)
  rpmdir = /usr/src/redhat
else
  rpmdir = $(wildcard ~/rpmdir)
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

  CFLAGS+=-fno-strict-aliasing -fno-common -fomit-frame-pointer -msoft-float -pipe -mminimal-toc -fno-builtin
endif

ifdef SMALL
  CFLAGS += -Os
else
  CFLAGS += -O2
endif

all: support_file bnx2.o

endif # ifeq ($(BCM_KVER),2.6)

bnx2.4.gz:
	gzip -c bnx2.4 > bnx2.4.gz

ifeq ($(BCM_KVER), 2.6)
install: default bnx2.4.gz
else
install: $(BCM_DRV) bnx2.4.gz
endif
	mkdir -p $(PREFIX)/$(BCMMODDIR);
	install -m 444 $(BCM_DRV) $(PREFIX)/$(BCMMODDIR);
	install -m 444 bnx2.4.gz $(PREFIX)/usr/share/man/man4;
	@if [ "$(PREFIX)" = "" ]; then /sbin/depmod -a ;\
	else echo " *** Run '/sbin/depmod -a' to update the module database.";\
	fi

.PHONEY: all support_file clean install

support_file:
	@if [ -n "$(SUSEVERS)" -a $(SUSEVERS) -ge 11 ]; then \
		echo "bnx2.ko external"  >  Module.supported; \
		echo "cnic.ko external"  >> Module.supported; \
	fi \

clean:
	-rm -f bnx2.o bnx2.ko bnx2.mod.c bnx2.mod.o bnx2.4.gz cnic.o cnic.ko cnic.mod.c cnic.mod.o Module.supported

