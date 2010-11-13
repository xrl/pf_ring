#!/bin/sh

IF=eth3

#service udev start
rmmod ixgbe
rmmod pf_ring
insmod ../../../../kernel/pf_ring.ko
modprobe ioatdma
:> /var/log/messages
# Set <id> as many times as the number of processors
insmod ./ixgbe.ko FdirMode=2,2,2,2,2,2 FdirPballoc=2,2,2,2,2,2
ifconfig $IF 1.2.3.4 up

cat /var/log/messages
