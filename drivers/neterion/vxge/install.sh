#!/bin/sh

TARGET=$1
PREFIX=$2

INST_ROOT=/lib/modules/`uname -r`
INST_DIR=updates
SUFFIX=drivers/net/vxge

#If driver has been installed previously to the wrong path, then remove it
rm -f $PREFIX/lib/modules/`uname -r`/kernel/drivers/net/$TARGET
rm -f $PREFIX/lib/modules/`uname -r`/updates/drivers/net/$TARGET

if [ -f /etc/SuSE-release ]; then
	SUSEVER=`cat /etc/SuSE-release | grep VERSION | cut -c 11-12`
	test $SUSEVER -lt 9 && INST_DIR=kernel
elif [ ! -d $INST_ROOT/$INST_DIR ]; then
	! grep -q "search.*[[:space:]]updates" /etc/depmod.conf /etc/depmod.d/* &> /dev/null && INST_DIR=kernel
fi

mkdir -p $PREFIX/$INST_ROOT/$INST_DIR/$SUFFIX
install -m 444 $TARGET $PREFIX/$INST_ROOT/$INST_DIR/$SUFFIX/

install -m 666 -d $PREFIX/usr/local/vxge/

install -m 666 vxge_intr.sh sysctl_neterion.conf vquery.sh $PREFIX/usr/local/vxge/
install -m 666 -d $PREFIX/lib/firmware/
install -m 666 X3*.ncf $PREFIX/lib/firmware/

if [ "$PREFIX" = "" ]; then
	/sbin/depmod -a
fi
