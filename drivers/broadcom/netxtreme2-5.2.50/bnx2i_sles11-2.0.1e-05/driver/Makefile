#!/usr/bin/make
# Makefile for building Linux Broadcom Gigabit L5 driver as a module.
# $id$
KVER=
ifeq ($(KVER),)
  KVER=$(shell uname -r)
endif

# PREFIX may be set by the RPM build to set the effective root.
PREFIX=
ifeq ($(shell ls /lib/modules/$(shell uname -r)/build > /dev/null 2>&1 && echo build),)
  ifeq ($(shell ls /usr/src/linux > /dev/null 2>&1 && echo linux),)
    LINUX=
  else
    LINUX=/usr/src/linux
  endif
else
  LINUX=/lib/modules/$(shell uname -r)/build
  ifeq ($(shell ls /lib/modules/$(shell uname -r)/source > /dev/null 2>&1 && echo source),)
    LINUXSRC=$(LINUX)
  else
    LINUXSRC=/lib/modules/$(shell uname -r)/source
  endif
endif

# Make sure only one bnx2? DKMS RPM is installed.
#ifneq ($(shell rpm -qa | grep -v "bnx2i-*" | grep "netxtreme2-.*dkms" | wc -l), 1)
    #$(error More than one netxtreme2 DKMS RPM installed!!!  Failing build.)
#endif

ifeq ($(BNX2_CNIC_INC),)
  # Obtain the current working directory.  $(PWD) doesn't work because this
  # makefile cannot override the $(PWD) definition of the parent makefile.
  BCMPWD = $(shell pwd)
  ifeq ($(shell test -e $(BCMPWD)/../../bnx2 > /dev/null 2>&1 || echo notfound),)
    BNX2_CNIC_INC := $(BCMPWD)/../../bnx2/src
  else
    ifneq ($(shell ls /usr/src/bnx2/bnx2.h /usr/src/bnx2/cnic_if.h > /dev/null 2>&1 && echo bnx2i),)
      BNX2_CNIC_INC := /usr/src/bnx2
    else
      $(error bnx2/cnic package not found. $(BCMPWD))
    endif
  endif
  export BNX2_CNIC_INC
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
        BCMMODDIR=/lib/modules/$(KVER)/kernel/drivers/scsi
      endif
    endif
  endif
endif

ifeq ($(shell grep scsi_get_resid $(LINUXSRC)/include/scsi/*.h > /dev/null 2>&1 && echo resid_defined),)
  BRCM_FLAGS = -D_DEFINE_SCSI_GET_RESID
endif

ifeq ($(shell grep scsi_set_resid $(LINUXSRC)/include/scsi/*.h > /dev/null 2>&1 && echo resid_defined),)
  BRCM_FLAGS += -D_DEFINE_SCSI_SET_RESID
endif

ifeq ($(shell awk '/(*create_session)/,/;/ {printf $$0; next}' $(LINUXSRC)/include/scsi/scsi_transport_iscsi.h | awk -F ',' '{print NF}'),6)
  BRCM_FLAGS += -D_CREATE_SESS_NEW_
endif

# check if 2.4 kernel or 2.5+ kernel
BCM_KVER:=$(shell uname -r | cut -c1-3 | sed 's/2\.[56]/2\.6/')

ifeq ($(BCM_KVER), 2.6)
BCM_DRV = bnx2i.ko
ARCH:=$(shell uname -m)
BCM_USR=../usr/bnx2id

BNX2ID_SCRIPT=
ifneq ($(shell ls /etc/redhat-release > /dev/null 2>&1 && echo rhel),)
    BNX2ID_SCRIPT=../etc/bnx2id.redhat
    BNX2ID_INIT_SCRIPT=/etc/rc.d/init.d/bnx2id
endif
ifneq ($(shell ls /etc/SuSE-release > /dev/null 2>&1 && echo rhel),)
    BNX2ID_SCRIPT=../etc/bnx2id.suse
    BNX2ID_INIT_SCRIPT=/etc/init.d/bnx2id
endif

ifneq ($(KERNELRELEASE),)
bnx2i-objs := bnx2i_iscsi.o bnx2i_hwi.o bnx2i_init.o bnx2i_sysfs.o bnx2i_ioctl.o
obj-m += bnx2i.o
EXTRA_CFLAGS += -ffast-math -mhard-float -I${BNX2_CNIC_INC} -D_SYSFS_INCL_ ${BRCM_FLAGS}
else # ($(KERNELRELEASE),)
default:
	make -C $(LINUX) SUBDIRS=$(shell pwd) modules
endif

else # ifeq ($(BCM_KVER),2.6)
# 2.4 kernel not supported
  $(error iSCSI Offload not supported on 2.4 kernel)
endif # ifeq ($(BCM_KVER),2.6)

install: default install_usr
	mkdir -p $(PREFIX)/$(BCMMODDIR)
	install -m 444 $(BCM_DRV) $(PREFIX)/$(BCMMODDIR)
	@if [ "$(PREFIX)" = "" ]; then /sbin/depmod -a $(KVER);\
	else echo " *** Run '/sbin/depmod -a' to update the module database.";\
	fi

install_usr:
	cd ../usr; make clean; make;
	install -D -m 755 ${BCM_USR} $(PREFIX)/sbin/bnx2id
	[ -n "${BNX2ID_SCRIPT}" ] && install -D -m 755 ${BNX2ID_SCRIPT} ${BNX2ID_INIT_SCRIPT}
	#chkconfig --level 6 bnx2id off
	chkconfig --level 0123456 bnx2id on

.PHONEY: all clean install

clean:
	rm -f bnx2i.o bnx2i.mod.[co] bnx2i_iscsi.o bnx2i_iscsi.mod.[co]
	rm -rf bnx2i_init.o bnx2i_init.mod.[co] bnx2i_ioctl.o bnx2i_ioctl.mod.[co]
	rm -rf .bnx2i*cmd bnx2i.ko .tmp_versions
	rm -rf .*.swp *.symvers
	rm -rf bnx2i_hwi.o bnx2i_sysfs.o bnx2i_hwi.mod.[co] bnx2i_swi.mod.[co]

cscope:
	find . -name "*.[ch]" > cscope.files
	cscope -bp3

tags:
	ctags -R
