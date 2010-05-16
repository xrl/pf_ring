#!/usr/bin/make

KVER=
ifeq ($(KVER),)
    KVER=$(shell uname -r)
endif

ifeq ($(shell test -f /etc/redhat-release > /dev/null 2>&1 || echo notfound),)
    MAJVER := $(shell sed -e 's/.*release \([0-9]\).*/\1/' /etc/redhat-release)
    ifeq ($(shell [ "$(MAJVER)" = "5" ] || echo notfound),)
        MINVER := $(shell sed -e 's/.*\.\([0-9]\)*.*/\1/' /etc/redhat-release)
        ifeq ($(shell [ $(MINVER) -lt 5 ] || echo notfound),)
            BCM_ISCSI_BUILD=iscsibuild
            BCM_ISCSI_INSTALL=iscsiinstall
            BCM_ISCSI_CLEAN=iscsiclean
            BCM_ISCSI_DIR=current
        endif
    endif
else
    MAJVER := $(shell grep VERSION /etc/SuSE-release | sed -e 's/.*= //')
    MINVER := $(shell grep PATCHLEVEL /etc/SuSE-release | sed -e 's/.*= //')
    ifeq ($(shell [ "$(MAJVER)" = "10" -a $(MINVER) -lt 4 -a $(MINVER) -gt 0 ] || echo notfound),)
        BCM_ISCSI_BUILD=iscsibuild
        BCM_ISCSI_INSTALL=iscsiinstall
        BCM_ISCSI_CLEAN=iscsiclean
        BCM_ISCSI_DIR=current
    endif
    ifeq ($(shell [ "$(MAJVER)" = "11" -a $(MINVER) -lt 1 ] || echo notfound),)
        BCM_ISCSI_BUILD=iscsibuild
        BCM_ISCSI_INSTALL=iscsiinstall
        BCM_ISCSI_CLEAN=iscsiclean
        BCM_ISCSI_DIR=sles11
    endif
endif


PREFIX=

default: build

symlink:
	[ -e bnx2i ] && rm bnx2i || /bin/true
	[ -n "$(BCM_ISCSI_DIR)" ] && ln -s $(BCM_ISCSI_DIR) bnx2i || /bin/true

l2build:
	make -C bnx2/src  KVER=$(KVER) PREFIX=$(PREFIX)
	make -C bnx2x/src KVER=$(KVER) PREFIX=$(PREFIX)

l2install:
	make -C bnx2/src  KVER=$(KVER) PREFIX=$(PREFIX) install
	make -C bnx2x/src KVER=$(KVER) PREFIX=$(PREFIX) install

l2clean:
	make -C bnx2/src  clean
	make -C bnx2x/src clean

iscsibuild: symlink
	[ -e bnx2/src/Module.symvers ] && cp -f bnx2/src/Module.symvers bnx2i/driver || /bin/true
	make -C bnx2i/driver KVER=$(KVER) PREFIX=$(PREFIX)

iscsiinstall:
	make -C bnx2i/driver KVER=$(KVER) PREFIX=$(PREFIX) install

iscsiclean:
	make -C bnx2i/driver clean

build: l2build $(BCM_ISCSI_BUILD)

install: build l2install $(BCM_ISCSI_INSTALL)

clean: l2clean $(BCM_ISCSI_CLEAN)

.PHONEY: all clean install
