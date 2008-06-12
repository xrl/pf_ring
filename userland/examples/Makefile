#
# Makefile for the PF_RING API example programs
#
# Try to make both programs written on top of the
# PF_RING library and programs originally written
# on top of PCAP library and linked now to use
# the version with PF_RING aware functionalities.
#
# Rocco Carbone <rocco /at/ ntop /dot/ org> - 2Q 2008 GPL
#


#
# Kernel
#
KERNELVER  = ${shell uname -r}
KERNELDIR  = /lib/modules/${KERNELVER}/source/include

#
# PF_RING
#
PFRINGDIR  = ../lib
LIBPFRING  = ${PFRINGDIR}/libpfring.a

#
# PF_RING aware libpcap
#
PCAPDIR    = ../libpcap-0.9.7-ring
LIBPCAP    = ${PCAPDIR}/libpcap.a

#
# Search directories
#
INCLUDE    = -I${KERNELDIR} -I${PFRINGDIR} -I${PCAPDIR}

#
# C compiler and flags
#
CC         = gcc
CFLAGS     = -g -Wall ${INCLUDE}
# LDFLAGS  =

#
# User and System libraries
#
LIBS       = ${LIBPFRING} -lpthread

# How to make an object file
%.o: %.c
#	@echo "=*= making object $@ =*="
	@${CC} ${CFLAGS} -c $< -o $@

#
# Main targets
#
PFPROGS   = ringc rings ringm pcaps pfcount forwarder
PCAPPROGS = pcount pwrite
TARGETS   = ${PFPROGS} ${PCAPPROGS}

RCOBJS    = ringc.o interval.o
RSOBJS    = rings.o interval.o
RMOBJS    = ringm.o interval.o
RPOBJS    = pcaps.o interval.o

all: ${TARGETS}

ringc: ${RCOBJS} ${LIBPFRING}
	@echo "=*= making program $@ =*="
	@${CC} ${RCOBJS} ${LIBS} -o $@

rings: ${RSOBJS} ${LIBPFRING}
	@echo "=*= making program $@ =*="
	@${CC} ${RSOBJS} ${LIBS} -o $@

ringm: ${RMOBJS} ${LIBPFRING}
	@echo "=*= making program $@ =*="
	@${CC} ${RMOBJS} ${LIBS} -o $@

pcaps: ${RPOBJS}
	@echo "=*= making program $@ =*="
	@${CC} ${RPOBJS} -lpcap -o $@

pfcount: pfcount.o ${LIBPFRING}
	@echo "=*= making program $@ =*="
	@${CC} pfcount.o ${LIBS} -o $@

forwarder: forwarder.o ${LIBPFRING}
	@echo "=*= making program $@ =*="
	@${CC} forwarder.o ${LIBS} -o $@

pcount: pcount.o ${LIBPCAP} ${LIBPFRING}
	@echo "=*= making program $@ =*="
	@${CC} pcount.o ${LIBPCAP} ${LIBS} -o $@

pwrite: pwrite.o ${LIBPCAP} ${LIBPFRING}
	@echo "=*= making program $@ =*="
	@${CC} pwrite.o ${LIBPCAP} ${LIBS} -o $@

clean:
	@rm -f ${TARGETS} *.o *~
