all: libpfring pcap ring_examples lib_c++ mod_perl


###################

libpfring:
	cd lib; make

pcap:
	cd libpcap-1.0.0-ring; ./configure;make

ring_examples:
	cd examples; make

lib_c++:
	cd c++; make

mod_perl:
	cd perl; make

###################

clean: libpfring_clean pcap_clean ring_examples_clean lib_c++_clean mod_perl_clean

libpfring_clean:
	cd lib; make clean

pcap_clean:
	if test -f libpcap-1.0.0-ring/config.status; then cd libpcap-1.0.0-ring; make clean; fi

ring_examples_clean:
	cd examples; make clean

lib_c++_clean:
	cd c++; make clean

mod_perl_clean:
	if test -f perl/Net-Pfring/Makefile; then cd perl; make clean; fi
