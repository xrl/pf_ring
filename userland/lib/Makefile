#
# Makefile for both static and dynamic PF_RING user libraries
#
# Luca Deri <deri /at/ ntop /dot/ org> - 2005-2008 GPL
# Rocco Carbone <rocco /at/ ntop /dot/ org> - 2Q 2008 GPL
#

#
# Installation directory
#
INSTDIR   = /usr/local

#
# Kernel
#
ifeq (,$(KERNELVER))
KERNELVER=$(shell uname -r)
endif
KERNELDIR = /lib/modules/${KERNELVER}/source/include

#
# Search directories
#
INCLUDE   = -I${KERNELDIR}

#
# Object files
#
OBJS      = pfring.o

#
# C compiler and flags
#
CC        = gcc
CFLAGS    = -g -O2 -Wall ${INCLUDE}
LDFLAGS   = -shared

SYSLIBS   = -lpthread

# How to make an object file
%.o: %.c
#	@echo "=*= making object $@ =*="
	@${CC} ${CFLAGS} -c $< -o $@

#
# Main targets
#
STATICLIB  = libpfring.a
DYNAMICLIB = libpfring.so
TARGETS    = ${STATICLIB} #${DYNAMICLIB}

all: ${TARGETS}

${STATICLIB}: ${OBJS}
	@echo "=*= making library $@ =*="
	@ar rs $@ ${OBJS}
	@ranlib $@

${DYNAMICLIB}: ${OBJS}
	@echo "=*= making library $@ =*="
	@${CC} ${LDFLAGS} $< ${SYSLIBS} -o $@

install: ${STATICLIB} ${DYNAMICLIB}
	cp ${STATICLIB} ${INSTDIR}/lib/
	cp ${DYNAMICLIB} ${INSTDIR}/lib/
	cp pfring.h ${INSTDIR}/include/

clean:
	@rm -f ${TARGETS} *.o *~
