# Specify here the 
KERNEL_VER=$(shell uname -r)
KERNEL_DIR=/lib/modules/$(KERNEL_VER)/source/include
INCLUDE=-I$(KERNEL_DIR)
OBJ=pfring.o
LIBPFRING=libpfring.a
TARGET=pfcount
F_TARGET=forwarder
RANLIB=ranlib
LIBS=-L../libpcap-0.9.7-ring -lpthread -lpcap
CC=gcc -g -Wall -pthread $(INCLUDE)

$(LIBPFRING): $(OBJ)
	@rm -f $@
	ar rc $@ $(OBJ)
	$(RANLIB) $@

install: $(LIBPFRING)
	cp $(LIBPFRING) /usr/local/lib
	cp pfring.h /usr/local/include
clean:
	/bin/rm -f $(TARGET) *.o *~ $(LIBPFRING)
