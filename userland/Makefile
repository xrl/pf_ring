all: libpfring pcap ring_examples lib_c++ mod_perl tcpdump

###################

libpfring:
	cd lib; ./configure; make

pcap:
	cd libpcap-1.1.1-ring; ./configure --enable-ipv6; make

ring_examples:
	cd examples; make

lib_c++:
	cd c++; make

mod_perl:
	cd perl; make

tcpdump:
	cd tcpdump-4.1.1; ./configure ; make

###################

clean: libpfring_clean pcap_clean ring_examples_clean lib_c++_clean mod_perl_clean tcpdump_clean

libpfring_clean:
	cd lib; make clean

pcap_clean:
	if test -f libpcap-1.1.1-ring/config.status; then cd libpcap-1.1.1-ring; make clean; fi

ring_examples_clean:
	cd examples; make clean

lib_c++_clean:
	cd c++; make clean

mod_perl_clean:
	if test -f perl/Net-Pfring/Makefile; then cd perl; make clean; fi

tcpdump_clean:
	if test -f tcpdump-4.1.1/config.status; then cd tcpdump-4.1.1; make clean; fi
