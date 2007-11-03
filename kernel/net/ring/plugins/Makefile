obj-m := dummy_plugin.o

all:
	make -C /lib/modules/$(shell uname -r)/build SUBDIRS=$(shell pwd) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build SUBDIRS=$(shell pwd) clean