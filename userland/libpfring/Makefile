CC=gcc -g

# Specify here the 
KERNEL_VER=$(shell uname -r)
KERNEL_DIR=/lib/modules/$(KERNEL_VER)/source/include
INCLUDE=-I$(KERNEL_DIR)
OBJ=pfring.o
LIBPFRING=libpfring.a
TARGET=pfcount
RANLIB=ranlib

$(TARGET): pfcount.o pfring.o $(LIBPFRING)
	$(CC) pfcount.o pfring.o -o $(TARGET)

$(LIBPFRING): $(OBJ)
	@rm -f $@
	ar rc $@ $(OBJ) $(LIBS)
	$(RANLIB) $@

pfring.o: pfring.c pfring.h
	$(CC) -c $(INCLUDE) $<

pfcount.o: pfcount.c
	$(CC) -c $(INCLUDE) $<

clean:
	/bin/rm -f $(TARGET) *.o *~
