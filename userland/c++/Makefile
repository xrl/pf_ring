CPP=g++ -g

# Specify here the 
KERNEL_VER=$(shell uname -r)
KERNEL_DIR=/lib/modules/$(KERNEL_VER)/source/include
LIBPCAP_DIR=../libpcap-0.9.7-ring
INCLUDE=-I$(KERNEL_DIR) -I$(LIBPCAP_DIR) -I../libpfring
LIBPFRING_CPP=libpfring_cpp.a
RANLIB=ranlib
OBJ=PFring.o
LIBS=-lpthread

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
