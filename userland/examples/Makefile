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
# PF_RING
#
PFRINGDIR  = ../lib
LIBPFRING  = ${PFRINGDIR}/libpfring.a

#
# DNA Support
DNA_DEFINE = #-DENABLE_DNA_SUPPORT

#
# PF_RING aware libpcap
#
PCAPDIR    = ../libpcap-1.0.0-ring
LIBPCAP    = ${PCAPDIR}/libpcap.a

#
# Search directories
#
INCLUDE    = -I../../kernel -I${PFRINGDIR} -I${PCAPDIR}

#
# C compiler and flags
#
CC         = gcc
CFLAGS     = -g -O2 -Wall ${INCLUDE} ${DNA_DEFINE}
# LDFLAGS  =

#
# User and System libraries
#
LIBS       = ${LIBPFRING} -lpthread

# How to make an object file
%.o: %.c
#	@echo "=*= making object $@ =*="
	${CC} ${CFLAGS} -c $< -o $@

#
# Main targets
#
PFPROGS   = ringc rings ringm pcaps pfcount pftwin ptwin pfreflect pfmap forwarder alldevs
PCAPPROGS = pcount pwrite
TARGETS   = ${PFPROGS} ${PCAPPROGS}

RCOBJS    = ringc.o interval.o
RSOBJS    = rings.o interval.o
RMOBJS    = ringm.o interval.o
RPOBJS    = pcaps.o interval.o

all: ${TARGETS}

ringc: ${RCOBJS} ${LIBPFRING}
	${CC} ${RCOBJS} ${LIBS} -o $@

rings: ${RSOBJS} ${LIBPFRING}
	${CC} ${RSOBJS} ${LIBS} -o $@

ringm: ${RMOBJS} ${LIBPFRING}
	${CC} ${RMOBJS} ${LIBS} -o $@

pcaps: ${RPOBJS}
	${CC} ${RPOBJS} ${LIBPCAP} ${LIBS} -o $@

pfcount: pfcount.o ${LIBPFRING}
	${CC} pfcount.o ${LIBS} -o $@

pfreflect: pfreflect.o ${LIBPFRING}
	${CC} pfreflect.o ${LIBS} -o $@

pftwin: pftwin.o ${LIBPFRING}
	${CC} pftwin.o ${LIBS} -o $@

ptwin: ptwin.o ${LIBPFRING}
	${CC} ptwin.o ${LIBPCAP} ${LIBS} -o $@

pfmap: pfmap.o ${LIBPFRING}
	${CC} pfmap.o ${LIBS} -o $@

forwarder: forwarder.o ${LIBPFRING}
	${CC} forwarder.o ${LIBS} -o $@

pcount: pcount.o ${LIBPCAP} ${LIBPFRING}
	${CC} pcount.o ${LIBPCAP} ${LIBS} -o $@

alldevs: alldevs.o ${LIBPCAP} ${LIBPFRING}
	${CC} alldevs.o ${LIBPCAP} ${LIBS} -o $@

pwrite: pwrite.o ${LIBPCAP} ${LIBPFRING}
	${CC} pwrite.o ${LIBPCAP} ${LIBS} -o $@

clean:
	@rm -f ${TARGETS} *.o *~
