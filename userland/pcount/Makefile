LIBPCAP=../libpcap-0.9.7-ring/libpcap.a
LIBPFRING=../libpfring/libpfring.a

pcount: pcount.c $(LIBPCAP) $(LIBPFRING) Makefile
	gcc -g pcount.c -o pcount $(LIBPCAP) $(LIBPFRING)

clean:
	\rm -f pcount *~