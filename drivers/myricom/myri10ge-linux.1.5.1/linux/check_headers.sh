#!/bin/bash
# $1 is the kernel build dir
# $2 is the kernel source dir (might be the same)
# $3 is the generated check file

if [ $# -lt 3 ] ; then
	echo "$0 needs KSRC, KDIR and OUTPUT as arguments"
	exit -1
fi

KSRC=$1
KDIR=$2
OUTPUT=$3

# Find where the headers are (to avoid grepping at both places).
# Do not check for autoconf.h or version.h since these are in
# both the source and the build directory.
HEADERS=
if [ -f ${KSRC}/include/linux/kernel.h ] ; then
	HEADERS=$KSRC
else if [ -f ${KDIR}/include/linux/kernel.h ] ; then
	HEADERS=$KDIR
fi fi

# check that we found kernel headers
if [ -z ${HEADERS} ] ; then
	echo "Cannot find include/linux/kernel.h in ${KSRC} or ${KDIR}"
	exit -1
fi
echo "Using kernel headers in ${HEADERS}"

# generate the output file
rm -f ${OUTPUT}

# add the header
echo "#ifndef __MYRI10GE_CHECKS_H__" >> ${OUTPUT}
echo "#define __MYRI10GE_CHECKS_H__ 1" >> ${OUTPUT}
echo "" >> ${OUTPUT}

# what command line was used to generate with file
echo "/*" >> ${OUTPUT}
echo " * This file has been generated with check_headers.sh on "`date` >> ${OUTPUT}
echo " * It has been called with:" >> ${OUTPUT}
echo " *   KSRC=${KSRC}" >> ${OUTPUT}
echo " *   KDIR=${KDIR}" >> ${OUTPUT}
echo " * It checked kernel headers in ${HEADERS}/include/" >> ${OUTPUT}
echo " */" >> ${OUTPUT}
echo "" >> ${OUTPUT}

# pci_save/restore_state lost its second argument in 2.6.10
grep "pci_save_state *(.*dev, .*buffer)" ${HEADERS}/include/linux/pci.h  > /dev/null \
  && echo "#define MYRI10GE_HAVE_PRIVATE_PM_STATE 1" >> ${OUTPUT} || true

# pm_message_t appeared in 2.6.11
grep pm_message_t ${HEADERS}/include/linux/pm.h > /dev/null \
  && echo "#define MYRI10GE_HAVE_PM_MESSAGE_T 1" >> ${OUTPUT} || true

# skb_linearize had a gfp argument before 2.6.18
grep "skb_linearize *(.*, .* gfp)" ${HEADERS}/include/linux/skbuff.h > /dev/null \
  && echo "#define MYRI10GE_SKB_LINEARIZE_HAS_GFP 1" >> ${OUTPUT} || true

# skb_padto returned a sk_buff before 2.6.18
grep "sk_buff \*skb_padto *(" ${HEADERS}/include/linux/skbuff.h > /dev/null \
  && echo "#define MYRI10GE_SKB_PADTO_RETURNS_SKB 1" >> ${OUTPUT} || true

# netdev_alloc_skb deprecates dev_alloc_skb in 2.6.18
grep "netdev_alloc_skb *(" ${HEADERS}/include/linux/skbuff.h > /dev/null \
  && echo "#define MYRI10GE_HAVE_NETDEV_ALLOC_SKB 1" >> ${OUTPUT} || true

# the irq handler losts its regs argument in 2.6.19
grep "irqreturn_t.*(.*)(int, void \*, struct pt_regs \*)" ${HEADERS}/include/linux/interrupt.h > /dev/null \
  && echo "#define MYRI10GE_HAVE_IRQ_HANDLER_REGS 1" >> ${OUTPUT} || true

# NAPI got reworked in 2.6.24
grep netif_napi_add ${HEADERS}/include/linux/netdevice.h > /dev/null \
  && echo "#define MYRI10GE_HAVE_NEW_NAPI 1" >> ${OUTPUT} || true

# skb_tail_pointer was added in 2.6.22
grep skb_tail_pointer ${HEADERS}/include/linux/skbuff.h > /dev/null \
  && echo "#define MYRI10GE_HAVE_SKB_TAIL_POINTER 1" >> ${OUTPUT} || true

# device attribute callbacks got an additional attribute in 2.6.13
grep show ${HEADERS}/include/linux/device.h | grep ssize_t | grep device_attribute > /dev/null \
  && echo "#define MYRI10GE_SYSFS_SHOW_STORE_3_ARGS 1" >> ${OUTPUT} || true

# __wsum was added in 2.6.20, but sles merged it back into their 2.6.16
grep __wsum ${HEADERS}/include/linux/types.h > /dev/null \
  && echo "#define MYRI10GE_HAVE_WSUM 1" >> ${OUTPUT} || true

# and Red Hat merged it into RHEL5u3, but put it into inet_lro.h!
if [ -f ${HEADERS}/include/linux/inet_lro.h ] ; then
    grep csum_unfold ${HEADERS}/include/linux/inet_lro.h > /dev/null \
	&& echo "#define MYRI10GE_HAVE_WSUM_IN_LRO_H 1" >> ${OUTPUT} || true
  fi;

if [ -f ${HEADERS}/include/linux/inet_lro.h ] ; then
    grep frag_align_pad ${HEADERS}/include/linux/inet_lro.h > /dev/null \
	&& echo "#define MYRI10GE_HAVE_LRO_FRAG_ALIGN 1" >> ${OUTPUT} || true
  fi;

# try to find __ioremap()  Somewhat tricky since they renamed the asm dir
# in the 2.6.24 timeframe
archname=`uname -m`
BITS=unknown
case ${archname} in
    i?86)
	ARCH=i386
	BITS=32
	;;
    x86_64)
	ARCH=x86_64
	BITS=64
	;;
    ia64)
	ARCH=ia64
	;;
    ppc64)
	ARCH=powerpc
	;;
    powerpc)
	ARCH=powerpc
	;;
    ppc)
	ARCH=powerpc
	;;
    *)
	ARCH=nopat
	;;
esac
if [ -d ${HEADERS}/arch/${ARCH}/include/asm ] ; then
    IOH=${HEADERS}/arch/${ARCH}/include/asm/io.h
elif [ -d ${HEADERS}/include/asm-${ARCH} ] ; then
    IOH=${HEADERS}/include/asm-${ARCH}/io.h
elif [ -d ${HEADERS}/include/asm-x86 ] ; then
    IOH=${HEADERS}/include/asm-x86/io_${BITS}.h
else
    IOH=/dev/null
fi

if [ -f ${IOH} ] ; then
    grep __ioremap ${IOH} > /dev/null && echo "#define MYRI10GE_HAVE___IOREMAP 1" >> ${OUTPUT} || true
    # mmiowb barrier
    grep mmiowb  ${IOH} > /dev/null \
	&& echo "#define MYRI10GE_HAVE_MMIOWB 1" >> ${OUTPUT} || true
fi

# ioremap_wc arrived in 2.6.26
grep ioremap_wc ${HEADERS}/include/asm-generic/iomap.h > /dev/null \
  && echo "#define MYRI10GE_HAVE_IOREMAP_WC 1" >> ${OUTPUT} || true

# alloc_etherdev_mq(), circa 2.6.25
grep alloc_etherdev_mq ${HEADERS}/include/linux/etherdevice.h > /dev/null \
  && echo "#define MYRI10GE_HAVE_ALLOC_ETHERDEV_MQ 1" >> ${OUTPUT} || true

# skb_get_queue_mapping(), circa 2.6.25
grep skb_get_queue_mapping ${HEADERS}/include/linux/skbuff.h > /dev/null \
  && echo "#define MYRI10GE_HAVE_SKB_GET_QUEUE_MAPPNG 1" >> ${OUTPUT} || true

# multiple tx queue support in 2.6.27
grep netdev_get_tx_queue ${HEADERS}/include/linux/netdevice.h > /dev/null \
  && echo "#define MYRI10GE_HAVE_MULTI_TX 1" >> ${OUTPUT} || true

# net device ops in 2.6.29
grep net_device_ops ${HEADERS}/include/linux/netdevice.h > /dev/null \
  && echo "#define MYRI10GE_HAVE_NET_DEVICE_OPS 1" >> ${OUTPUT} || true

# netif_rx_* lost its first netdev argument in 2.6.29, becoming similar to napi_*, which replaced it in 2.6.30
grep "^static inline void netif_rx_complete(struct net_device" ${HEADERS}/include/linux/netdevice.h > /dev/null \
  && echo "#define MYRI10GE_HAVE_NETIF_RX_WITH_NETDEV 1" >> ${OUTPUT} || true

# skb_record_rx_queue added in 2.6.30
grep skb_record_rx_queue ${HEADERS}/include/linux/skbuff.h > /dev/null \
  && echo "#define MYRI10GE_HAVE_SKB_RECORD_RX_QUEUE 1" >> ${OUTPUT} || true


if [ -f /etc/issue ] ; then
	grep 'SUSE Linux Enterprise Server 11' /etc/issue > /dev/null \
		&& echo "#define MYRI10GE_NEED_SUPPORTED 1" >>  ${OUTPUT} || true
fi

# module parameter arrays, early in 2.6
grep module_param_array_named ${HEADERS}/include/linux/moduleparam.h > /dev/null \
  && grep ARRAY_SIZE  ${HEADERS}/include/linux/moduleparam.h | grep nump > /dev/null \
  && echo "#define MYRI10GE_HAVE_MODP_ARRAY 1" >> ${OUTPUT} || true

grep ethtool_op_set_flags  ${HEADERS}/include/linux/ethtool.h > /dev/null \
    && echo "#define MYRI10GE_HAVE_ETHTOOL_FLAGS 1" >> ${OUTPUT} || true

# vlan features from 2.6.26
grep vlan_features ${HEADERS}/include/linux/netdevice.h > /dev/null \
  && echo "#define MYRI10GE_HAVE_VLAN_FEATURES 1" >> ${OUTPUT} || true

# csum_ipv6_magic needed for ia64, sometimes found here
# it moved here from checksum.h early in 2.6.x
if [ -f ${HEADERS}/include/net/ip6_checksum.h ] ; then
    echo "#define MYRI10GE_HAVE_IPV6_CHECKSUM_H 1" >>  ${OUTPUT}
fi

# GRO for skbs from 2.6.29
grep napi_gro_receive ${HEADERS}/include/linux/netdevice.h > /dev/null \
  && echo "#define MYRI10GE_HAVE_GRO_SKB 1" >> ${OUTPUT} || true

# GRO for frags pending for 2.6.31
grep napi_get_frags ${HEADERS}/include/linux/netdevice.h > /dev/null \
  && echo "#define MYRI10GE_HAVE_GRO_FRAGS 1" >> ${OUTPUT} || true

# The core updates trans_start starting with 2.6.31
grep txq_trans_update ${HEADERS}/include/linux/netdevice.h > /dev/null \
  || echo "#define MYRI10GE_NEED_TRANS_START_UPDATE 1" >> ${OUTPUT} || true

# netdev_tx_t added in 2.6.32
grep netdev_tx_t ${HEADERS}/include/linux/netdevice.h > /dev/null \
  && echo "#define MYRI10GE_HAVE_NETDEV_TX_T 1" >> ${OUTPUT} || true


# add the footer
echo "" >> ${OUTPUT}
echo "#endif /* __MYRI10GE_CHECKS_H__ */" >> ${OUTPUT}
