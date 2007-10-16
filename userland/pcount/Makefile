LIBPCAP=../libpcap-0.9.7-ring/libpcap.a
LIBPFRING=../libpfring/libpfring.a
KERNEL_VER=$(shell uname -r)
KERNEL_DIR=/lib/modules/$(KERNEL_VER)/source/include
INCLUDE=-I$(KERNEL_DIR)

all: pcount pwrite

pcount: pcount.c $(LIBPCAP) $(LIBPFRING) Makefile
	gcc -g pcount.c -o pcount $(LIBPCAP) $(LIBPFRING)

pwrite: pwrite.c $(LIBPCAP) $(LIBPFRING) Makefile
	gcc $(INCLUDE) -g pwrite.c -o pwrite $(LIBPCAP) $(LIBPFRING)

clean:
	\rm -f pcount pwrite *~