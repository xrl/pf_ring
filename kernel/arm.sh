#!/bin/sh

#
# Simple file for cross-compiling PF_RING on ARM
#
make -C ../../kernel/linux-feroceon_5_0_3_KW SUBDIRS=/home/deri/ARM/PF_RING/kernel EXTRA_CFLAGS='-I/home/deri/ARM/PF_RING/kernel' ARCH=arm CROSS_COMPILE=arm-mv5sft-linux-gnueabi- modules
