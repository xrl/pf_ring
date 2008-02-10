CC=gcc -g -Wall -pthread

# Specify here the 
KERNEL_VER=$(shell uname -r)
KERNEL_DIR=/lib/modules/$(KERNEL_VER)/source/include
INCLUDE=-I$(KERNEL_DIR)
OBJ=pfring.o
LIBPFRING=libpfring.a
TARGET=pfcount
RANLIB=ranlib
LIBS=-lpthread -lpcap

all: $(TARGET)

$(TARGET): pfcount.o $(LIBPFRING)
	$(CC) pfcount.o $(LIBPFRING) -o $(TARGET) $(LIBS)

$(LIBPFRING): $(OBJ)
	@rm -f $@
	ar rc $@ $(OBJ)
	$(RANLIB) $@

pfring.o: pfring.c pfring.h
	$(CC) -c $(INCLUDE) $<

pfcount.o: pfcount.c
	$(CC) -c $(INCLUDE) $<

install: $(LIBPFRING)
	cp $(LIBPFRING) /usr/local/lib
	cp pfring.h /usr/local/include
clean:
	/bin/rm -f $(TARGET) *.o *~ $(LIBPFRING)
