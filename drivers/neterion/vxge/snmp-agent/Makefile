#
# Makefile for the net-snmp agent for vxge driver.
# Copyright(c) 2002-2010 Exar Inc.
#

AGENT_PREFIX=vxge
INSTALL_PREFIX=

NETSNMPCONFIG=net-snmp-config

# uncomment this if you have GNU make
NETSNMPCFLAGS := $(shell $(NETSNMPCONFIG) --base-cflags)
NETSNMPLIBS := $(shell $(NETSNMPCONFIG) --agent-libs)
#NETSNMPCFLAGS=`$(NETSNMPCONFIG) --base-cflags`
#NETSNMPLIBS=`$(NETSNMPCONFIG) --agent-libs`

LIBS=$(NETSNMPLIBS)

CC=gcc
TOPDIR=/usr/include/net-snmp
INCLUDEDIR= -I. -I$(TOPDIR) -I$(TOPDIR)/snmplib \
		-I$(TOPDIR)/agent -I$(TOPDIR)/agent/mibgroup \
		-I$(TOPDIR)/library
STRICT_FLAGS = -Wall -Wstrict-prototypes
CFLAGS=$(INCLUDEDIR) $(NETSNMPCFLAGS) $(STRICT_FLAGS)
LDFLAGS=-fPIC -shared 

OBJS =  $(AGENT_PREFIX)-agent.o \
	$(AGENT_PREFIX)-data.o \
	$(AGENT_PREFIX)-dev.o

TARGET=$(AGENT_PREFIX).so

.SUFFIXES:
.SUFFIXES: .c .o .deps

all: $(TARGET)

.c.o:
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ -c $<

$(TARGET): $(OBJS) Makefile
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)

install:
	sh install.sh $(INSTALL_PREFIX)

clean:
	rm -f $(OBJS) $(TARGET)

