PCAP=../libpcap-0.8.1

pcount: pcount.c Makefile
	gcc -I$(PCAP) -g pcount.c -o pcount -L$(PCAP) -lpcap
