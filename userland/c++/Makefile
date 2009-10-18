CPP=g++ -g 

KERNEL_DIR=../../kernel
LIBPCAP_DIR=../libpcap-1.0.0-ring
INCLUDE=-I$(KERNEL_DIR) -I$(LIBPCAP_DIR) -I../lib
LIBPFRING_CPP=libpfring_cpp.a
RANLIB=ranlib
OBJ=PFring.o
LIBS=../lib/libpfring.a -lpthread 

all: $(LIBPFRING_CPP) pf_test

pf_test: pf_test.cpp $(LIBPFRING_CPP)
	$(CPP) $(INCLUDE) $< $(LIBPFRING_CPP) $(LIBPCAP_DIR)/libpcap.a -o $@ $(LIBS)

$(LIBPFRING_CPP): $(OBJ)
	@rm -f $@
	ar rc $@ $(OBJ) $(LIBPFRING_CPP)
	$(RANLIB) $@

PFring.o: PFring.cpp PFring.h
	$(CPP) -c $(INCLUDE) $<

clean:
	/bin/rm -f $(TARGET) *.o *~ $(LIBPFRING_CPP) pf_test
