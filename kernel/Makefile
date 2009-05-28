#
# (C) 2009 - Luca Deri <deri@ntop.org>
#

obj-m := ring.o

# set the install path
INSTDIR := /lib/modules/$(shell uname -r)/kernel/net/ring

all: Makefile ring.c ring.h
	make -C /lib/modules/$(shell uname -r)/build SUBDIRS=$(shell pwd) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build SUBDIRS=$(shell pwd) clean
	\rm -f *~ Module.symvers  Module.markers  modules.order *#

install: all
	mkdir -p $(INSTDIR)
	cp *.ko $(INSTDIR)
