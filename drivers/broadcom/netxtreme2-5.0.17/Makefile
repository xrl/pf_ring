#!/usr/bin/make

KVER=
ifeq ($(KVER),)
    KVER=$(shell uname -r)
endif

PREFIX=

default:
	make -C bnx2/src  KVER=$(KVER) PREFIX=$(PREFIX)
	make -C bnx2x/src KVER=$(KVER) PREFIX=$(PREFIX)

install:
	make -C bnx2/src  KVER=$(KVER) PREFIX=$(PREFIX) install
	make -C bnx2x/src KVER=$(KVER) PREFIX=$(PREFIX) install

clean:
	make -C bnx2/src  clean
	make -C bnx2x/src clean

.PHONEY: all clean install
