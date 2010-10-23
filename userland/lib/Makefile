#
# Makefile for both static and dynamic PF_RING user libraries
#
# Luca Deri <deri /at/ ntop /dot/ org> - 2005-2008 GPL
# Rocco Carbone <rocco /at/ ntop /dot/ org> - 2Q 2008 GPL
#

#
# Installation directory
#
INSTDIR   = ${DESTDIR}/usr/local

#
# Search directories
#
INCLUDE   = -I../../kernel

#
# DNA Support
#
DNA_OBJS   = pfring_e1000e_dna.o
DNA_DEFINE =

#
# Object files
#
OBJS      = pfring.o ${DNA_OBJS}

#
# C compiler and flags
#
#
# CROSS_COMPILE=arm-mv5sft-linux-gnueabi-
#
CC        = ${CROSS_COMPILE}gcc
CFLAGS    = -g  -Wall -fPIC ${INCLUDE} ${DNA_DEFINE}
LDFLAGS   = -g -shared

SYSLIBS   = -lpthread

# How to make an object file
%.o: %.c %.h
#	@echo "=*= making object $@ =*="
	${CC} ${CFLAGS} -c $< -o $@

#
# Main targets
#
STATICLIB  = libpfring.a
DYNAMICLIB = libpfring.so
TARGETS    = ${STATICLIB} ${DYNAMICLIB}
RING_H     = ../../kernel/linux/pf_ring.h

all: ${TARGETS}

${STATICLIB}: Makefile ${OBJS} pfring.h ${RING_H}
	@echo "=*= making library $@ =*="
	ar rs $@ ${OBJS}
	ranlib $@

${DYNAMICLIB}: ${OBJS} pfring.h ${RING_H} Makefile
	@echo "=*= making library $@ =*="
	${CC} ${LDFLAGS} ${OBJS} ${SYSLIBS} -o $@

install: ${STATICLIB} ${DYNAMICLIB}
	cp ${STATICLIB} ${INSTDIR}/lib/
	cp ${DYNAMICLIB} ${INSTDIR}/lib/
	cp pfring_e1000e_dna.h pfring.h ${INSTDIR}/include/
	ldconfig

clean:
	@rm -f ${TARGETS} *.o *~
