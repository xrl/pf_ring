CC=gcc -g -Wall -pthread

# Specify here the 
KERNEL_VER=$(shell uname -r)
KERNEL_DIR=/lib/modules/$(KERNEL_VER)/source/include
INCLUDE=-I$(KERNEL_DIR)
CFLAGS= -g -Wall ${INCLUDE}
OBJ=pfring.o
LIBPFRING=libpfring.a
RANLIB=ranlib
LIBS=-L../libpcap-0.9.7-ring -lpthread #-lpcap

# How to make an object file
%.o: %.c
	${CC} ${CFLAGS} -c $< -o $@

all: $(LIBPFRING)

$(LIBPFRING): $(OBJ)
	@rm -f $@
	ar rc $@ $(OBJ)
	$(RANLIB) $@

install: $(LIBPFRING)
	cp $(LIBPFRING) /usr/local/lib
	cp pfring.h /usr/local/include
clean:
	/bin/rm -f *.o *~ $(LIBPFRING)
