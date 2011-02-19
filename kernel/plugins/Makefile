obj-m := dummy_plugin.o

EXTRA_CFLAGS += -I$(PWD)/..

all:
	make -C /lib/modules/$(shell uname -r)/build SUBDIRS=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build SUBDIRS=$(PWD) clean
