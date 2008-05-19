CC=gcc -g -Wall -pthread

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

all: $(TARGET) $(F_TARGET)

$(TARGET): pfcount.o $(LIBPFRING)
	$(CC) pfcount.o $(LIBPFRING) -o $(TARGET) $(LIBS)

$(F_TARGET): $(F_TARGET).o $(LIBPFRING)
	$(CC) $(F_TARGET).o $(LIBPFRING) -o $(F_TARGET) $(LIBS)

$(LIBPFRING): $(OBJ)
	@rm -f $@
	ar rc $@ $(OBJ)
	$(RANLIB) $@

pfring.o: pfring.c pfring.h
	$(CC) -c $(INCLUDE) $<

forwarder.o: forwarder.c pfring.h
	$(CC) -c $(INCLUDE) $<

pfcount.o: pfcount.c
	$(CC) -c $(INCLUDE) $<

install: $(LIBPFRING)
	cp $(LIBPFRING) /usr/local/lib
	cp pfring.h /usr/local/include
clean:
	/bin/rm -f $(TARGET) *.o *~ $(LIBPFRING)
