#
# Makefile for Neterion Inc's X3100 Series 10GbE PCIe I/O Virtualized
# Server Adapter.
#

CONFIG_NETERION_XGE=m

CONFIG_VXGE_DEBUG_ASSERT=n
CONFIG_VXGE_DEBUG_TRACE=y
CONFIG_VXGE_DEBUG_TRACE_ALL=n

CONFIG_VXGE_SNMP=y

CONFIG_VXGE_USE_FW_HEADER_FILE=y
CONFIG_VXGE_SELF_TEST=y

CONFIG_VXGE_PF_RING=y

INCLUDEDIR:=$(shell uname -r | sed 's/\([0-9]*\.[0-9]*\)\..*/\1/')

# PREFIX may be set by the RPM build to set the effective root.
PREFIX=
ifeq ($(shell ls /lib/modules/`uname -r`/build > /dev/null 2>&1 && echo build),)
  ifeq ($(shell ls /usr/src/linux > /dev/null 2>&1 && echo linux),)
    LINUX=
  else
    LINUX=/usr/src/linux
  endif
else
  LINUX=/lib/modules/`uname -r`/build
endif
ifeq ($(LINUX),)
  $(error Linux kernel source tree not found)
endif

ifeq ($(shell [ -e /etc/SuSE-release ] && echo 1),1)
	SUSEVERS = $(shell grep VERSION /etc/SuSE-release | sed -e 's/.*= //' | awk -F '.' '{print $$1;}')
else
	SUSEVERS = 0
endif

ifeq ($(CONFIG_VXGE_DEBUG_ASSERT),y)
EXTRA_CFLAGS += -DVXGE_DEBUG_ASSERT -g
endif

ifeq ($(CONFIG_VXGE_USE_FW_HEADER_FILE),y)
EXTRA_CFLAGS += -DVXGE_USE_FW_HEADER_FILE -g
endif

ifeq ($(CONFIG_VXGE_SNMP),y)
EXTRA_CFLAGS += -DVXGE_SNMP
endif

ifeq ($(CONFIG_VXGE_DEBUG_CODE),y)
EXTRA_CFLAGS += -DVXGE_DEBUG_CODE
endif

ifeq ($(CONFIG_VXGE_SELF_TEST),y)
EXTRA_CFLAGS += -DVXGE_SELF_TEST
endif

ifeq ($(CONFIG_VXGE_PF_RING),y)
PF_RING_SRC_DIR = $(PWD)/../../kernel/
EXTRA_CFLAGS += -DVXGE_PF_RING -I$(PF_RING_SRC_DIR)
endif

#Uncomment this line to support KERNEL GRO
#EXTRA_CFLAGS += -DVXGE_KERNEL_GRO
#Uncomment this line to dump RXD Err packets
#EXTRA_CFLAGS += -DVXGE_RX_ERR_DBG
#Uncomment this line to enable loopback mode in the driver
#EXTRA_CFLAGS += -DVXGE_LOOPBACK_TEST

# The following flag will trace the init path.
# change the bit mask to trace a different set of modules.
#
# VXGE trace enabling, bitmask definitions
#	VXGE_DEBUG_INIT					0x00000001
#	VXGE_DEBUG_TX					0x00000002
#	VXGE_DEBUG_RX					0x00000004
#	VXGE_DEBUG_MEM					0x00000008
#	VXGE_DEBUG_LOCK					0x00000010
#	VXGE_DEBUG_SEM					0x00000020
#	VXGE_DEBUG_ENTRYEXIT				0x00000040
#	VXGE_DEBUG_INTR					0x00000080
#	VXGE_DEBUG_LL_CONFIG				0x00000100

#	VXGE_COMPONENT_HAL_DEVICE			0x00000001
#	VXGE_COMPONENT_HAL_DEVICE_IRQ			0x00000002
#	VXGE_COMPONENT_HAL_VPATH			0x00000004
#	VXGE_COMPONENT_HAL_VPATH_IRQ			0x00000008
#	VXGE_COMPONENT_HAL_CONFIG			0x00000010
#	VXGE_COMPONENT_HAL_MM				0x00000020
#	VXGE_COMPONENT_HAL_POOL				0x00000040
#	VXGE_COMPONENT_HAL_QUEUE			0x00000080
#	VXGE_COMPONENT_HAL_BITMAP			0x00000100
#	VXGE_COMPONENT_HAL_CHANNEL			0x00000200
#	VXGE_COMPONENT_HAL_FIFO				0x00000400
#	VXGE_COMPONENT_HAL_RING				0x00000800
#	VXGE_COMPONENT_HAL_DMQ				0x00001000
#	VXGE_COMPONENT_HAL_UMQ				0x00002000
#	VXGE_COMPONENT_HAL_SQ				0x00004000
#	VXGE_COMPONENT_HAL_SRQ				0x00008000
#	VXGE_COMPONENT_HAL_CQRQ				0x00010000
#	VXGE_COMPONENT_HAL_NCE				0x00020000
#	VXGE_COMPONENT_HAL_STAG				0x00040000
#	VXGE_COMPONENT_HAL_TCP				0x00080000
#	VXGE_COMPONENT_HAL_LRO				0x00100000
#	VXGE_COMPONENT_HAL_SPDM				0x00200000
#	VXGE_COMPONENT_HAL_SESSION			0x00400000
#	VXGE_COMPONENT_HAL_STATS			0x00800000
#	VXGE_COMPONENT_OSDEP				0x10000000
#	VXGE_COMPONENT_LL				0x20000000
#	VXGE_COMPONENT_ALL				0xffffffff

ifeq ($(CONFIG_VXGE_DEBUG_TRACE_ALL),y)
EXTRA_CFLAGS += -DVXGE_DEBUG_MODULE_MASK=0xffffffff\
	        -DVXGE_DEBUG_TRACE_MASK=0xffffffff\
		-DVXGE_DEBUG_ERR_MASK=0xffffffff\
		-DVXGE_DEBUG_MASK=0x000001FF
else
ifeq ($(CONFIG_VXGE_DEBUG_TRACE),y)
EXTRA_CFLAGS += -DVXGE_DEBUG_MODULE_MASK=0x20000000\
		-DVXGE_DEBUG_TRACE_MASK=0x20000000\
		-DVXGE_DEBUG_ERR_MASK=0x20000000\
		-DVXGE_DEBUG_MASK=0x00000001
else
ifeq ($(CONFIG_VXGE_DEBUG_TRACE),n)
EXTRA_CFLAGS += -DVXGE_DEBUG_MODULE_MASK=0x0\
		-DVXGE_DEBUG_TRACE_MASK=0x0\
		-DVXGE_DEBUG_ERR_MASK=0x0\
		-DVXGE_DEBUG_MASK=0x0
endif
endif
endif

EXTRA_CFLAGS += -I$(obj)/.. -DLINUX

obj-$(CONFIG_NETERION_XGE) += vxge.o

vxge-y := $(EXTRA_OBJS) vxge-config.o vxge-traffic.o vxge-main.o vxge-ethtool.o

KVER := $(shell uname -r)
KINST := /lib/modules/$(KVER)/kernel/drivers/net/vxge/
KSRC := /lib/modules/$(KVER)/build
KSRC_OUTPUT := $(KSRC)
PWD=$(shell pwd)

VERFILE := $(KSRC_OUTPUT)/include/linux/version.h
KERNELRELEASE := $(shell \
	if [ -r $(VERFILE) ]; then \
		(cat $(VERFILE); echo UTS_RELEASE) | \
		$(CC) -I$(KSRC_OUTPUT) $(CFLAGS) -E - | \
		tail -n 1 | \
		xargs echo; \
        else \
		uname -r; \
	fi)
KERNELMINOR := $(shell echo $(KERNELRELEASE) | awk -F. '{print $$2}')

MODPATH := $(DESTDIR)/lib/modules/$(KERNELRELEASE)
TMP=$(PWD)/tmp

all: modules
release: remove_snmp_code     remove_pf_ring_code 

remove_pf_ring_code:
ifeq ($(CONFIG_VXGE_PF_RING),n)
	../misc/remove_PF_RING_CODE.pl
endif

remove_snmp_code:
ifeq ($(CONFIG_VXGE_SNMP),n)
	../misc/remove_SNMP.pl
endif

ifeq ($(ARCH),powerpc)
EXTRA_CFLAGS += -D__BIG_ENDIAN
CC = $(CROSS_COMPILE)gcc
endif

clean:
	rm -f $(vxge-y)
	rm -f *.mod.c *.mod *.o *.ko .*.cmd .*.flags  modules.order Module.symvers Module.supported
	rm -rf $(PWD)/tmp

ifeq ($(KERNELMINOR), 4)
# Linux 2.4 section
ARCH=$(shell arch)
ifeq ($(ARCH), x86_64)
MCMODEL=-mcmodel=kernel
else
MCMODEL=
endif
LD = $(CROSS_COMPILE)ld
CC = $(CROSS_COMPILE)gcc
KDIR := /lib/modules/$(shell uname -r)/build

CFLAGS += -DLINUX -DMODULE -D__KERNEL__ -I$(KDIR)/include -I . -I ../ -Wall \
	  -Wstrict-prototypes $(MCMODEL) -O2 -include $(KDIR)/include/linux/modversions.h $(EXTRA_CFLAGS)

modules: vxge.o
vxge.o:  vxge-config.h vxge-traffic.h vxge-main.h  vxge-ethtool.h vxge-reg.h vxge-version.h $(vxge-y)
	$(LD) -r -o $@ $(vxge-y) `$(CC) -print-file-name=libgcc.a`

vxge.o: modules

TARGET = vxge.o

else
# Linux 2.6 section
modules: module_supported
	$(MAKE) -C $(KSRC) SUBDIRS=$(PWD) modules

vxge.ko: modules

TARGET = vxge.ko

module_supported:
	@if [ $(SUSEVERS) -ge 9 ]; then \
		echo "$(TARGET) external" > Module.supported; \
	fi
endif

install: $(TARGET)
	sh install.sh $(TARGET) $(PREFIX);
