PCAP_DIR=../libpcap-0.9.7-ring
LIBPCAP=$(PCAP_DIR)/libpcap.a
LIBPFRING=../lib/libpfring.a
KERNEL_VER=$(shell uname -r)
KERNEL_DIR=/lib/modules/$(KERNEL_VER)/source/include
INCLUDE=-I$(KERNEL_DIR) -I$(PCAP_DIR) -I../lib
LIBS=-lpthread

all: pfcount forwarder pcount pwrite

pfcount: pfcount.c $(LIBPCAP) $(LIBPFRING) Makefile
	gcc $(INCLUDE) -g pfcount.c -o pfcount $(LIBPFRING) $(LIBS)

forwarder: forwarder.c $(LIBPCAP) $(LIBPFRING) Makefile
	gcc $(INCLUDE) -g forwarder.c -o forwarder $(LIBPFRING) $(LIBS)

pcount: pcount.c $(LIBPCAP) $(LIBPFRING) Makefile
	gcc $(INCLUDE) -g pcount.c -o pcount $(LIBPCAP) $(LIBPFRING) $(LIBS)

pwrite: pwrite.c $(LIBPCAP) $(LIBPFRING) Makefile
	gcc $(INCLUDE) -g pwrite.c -o pwrite $(LIBPCAP) $(LIBPFRING) $(LIBS)

clean:
	\rm -f pfcount forwarder pcount pwrite *~