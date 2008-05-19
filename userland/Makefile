all: lib pcap examples c++ perl

###################

lib:
	cd lib; make

pcap:
	cd libpcap-0.9.7-ring; ./configure;make

examples:
	cd examples; make

c++:
	cd c++; make

perl:
	cd perl; make

###################

clean: lib_clean pcap_clean examples_clean c++_clean perl_clean

lib_clean:
	cd lib; make clean

pcap_clean:
	cd libpcap-0.9.7-ring; make clean

examples_clean:
	cd examples; make clean

c++_clean:
	cd c++; make clean

perl_clean:
	cd perl; make clean