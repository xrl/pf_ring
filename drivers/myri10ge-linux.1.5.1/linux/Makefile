MYRI10GE_LRO=1
MYRI10GE_BUILTIN_FW=0
MYRI10GE_ALLOC_ORDER=0
MYRI10GE_RX_SKBS=0
MYRI10GE_VPUMP=0
MYRI10GE_THROTTLE=0
MYRI10GE_JUMBO=0
MYRI10GE_KERNEL_LRO=1

ifneq ($(KERNELRELEASE),)
EXTRA_CFLAGS	=	-DMYRI10GE_LRO=$(MYRI10GE_LRO)
EXTRA_CFLAGS	+=	-DMYRI10GE_BUILTIN_FW=$(MYRI10GE_BUILTIN_FW)
EXTRA_CFLAGS	+=	-DMYRI10GE_ALLOC_ORDER=$(MYRI10GE_ALLOC_ORDER)
EXTRA_CFLAGS	+=	-DMYRI10GE_RX_SKBS=$(MYRI10GE_RX_SKBS)
EXTRA_CFLAGS	+=	-DMYRI10GE_VPUMP=$(MYRI10GE_VPUMP)
EXTRA_CFLAGS	+=	-DMYRI10GE_THROTTLE=$(MYRI10GE_THROTTLE)
EXTRA_CFLAGS	+=	-DMYRI10GE_JUMBO=$(MYRI10GE_JUMBO)
EXTRA_CFLAGS	+=	-DMYRI10GE_KERNEL_LRO=$(MYRI10GE_KERNEL_LRO)
EXTRA_CFLAGS	+=	$(DCA_FLAGS)
obj-m	:= myri10ge.o

else
KVER	:= $(shell uname -r)
KDIR	:= /lib/modules/$(KVER)/build
KSRC	:= /lib/modules/$(KVER)/source
PWD	:= $(shell pwd)

check_header := $(shell							  \
	if test -r myri10ge_checks.h &&					  \
	   test "`grep KDIR myri10ge_checks.h`" != " *   KDIR=$(KDIR)" -o \
	   "`grep KSRC myri10ge_checks.h`" != " *   KSRC=$(KSRC)" ; then  \
	   rm -f myri10ge_checks.h ;					  \
	fi)

default: myri10ge_version.h myri10ge_checks.h
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

ifeq ($(MYRI10GE_VPUMP),1)
EXTRA_VERSION="vpump"
else
EXTRA_VERSION=""
endif

myri10ge_version.h: VERSION
	./make_version $(EXTRA_VERSION)

myri10ge_checks.h: check_headers.sh
	./check_headers.sh $(KSRC) $(KDIR) myri10ge_checks.h

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f myri10ge_version.h myri10ge_checks.h Module.symvers

help:
	$(MAKE) -C $(KDIR) M=$(PWD) help

KTREE_DRV := /lib/modules/$(KVER)/kernel/drivers/net/myri10ge

install : default install-only

install-only: 
	@for FW_DIR in /lib/firmware /usr/lib/hotplug/firmware; do 	\
		if test -d $$FW_DIR; then 				\
			for i in ../firmware/*dat; do			\
				dest=$$FW_DIR/myri10ge_`basename $$i`;	\
				echo "Installing $$i to $$dest";	\
				cp $$i $$dest;				\
			done						\
		fi;							\
	done
	rm -f /lib/modules/$(KVER)/extra/myri10ge.ko
	@if test -r $(KTREE_DRV)/myri10ge.ko; then \
		mv -f $(KTREE_DRV)/myri10ge.ko $(KTREE_DRV)/myri10ge.ko.distrib;\
	fi
	mkdir -p /lib/modules/$(KVER)/extra
	cp myri10ge.ko /lib/modules/$(KVER)/extra/.
	/sbin/depmod $(KVER)

linux-tree: myri10ge_version.h
	./generate_linux_tree.sh

endif
