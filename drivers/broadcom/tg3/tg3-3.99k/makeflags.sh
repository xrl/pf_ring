#!/bin/sh

if grep -q "netdump_mode" $1/include/linux/kernel.h ; then
	echo "#define BCM_HAS_NETDUMP_MODE"
fi

if grep -q "bool" $1/include/linux/types.h ; then 
	echo "#define BCM_HAS_BOOL"
fi

if grep -q "__le32" $1/include/linux/types.h ; then 
	echo "#define BCM_HAS_LE32"
fi

if grep -q "resource_size_t" $1/include/linux/types.h ; then
	echo "#define BCM_HAS_RESOURCE_SIZE_T"
fi

if grep -q "kzalloc" $1/include/linux/slab.h ; then
	echo "#define BCM_HAS_KZALLOC"
fi

for symbol in jiffies_to_usecs usecs_to_jiffies msecs_to_jiffies; do
	if [ -f $1/include/linux/jiffies.h ]; then
		if grep -q "$symbol" $1/include/linux/jiffies.h ; then
			echo "#define BCM_HAS_`echo $symbol | tr '[a-z]' '[A-Z]'`"
			continue
		fi
	fi
	if [ -f $1/include/linux/time.h ]; then
		if grep -q "$symbol" $1/include/linux/time.h ; then
			echo "#define BCM_HAS_`echo $symbol | tr '[a-z]' '[A-Z]'`"
			continue
		fi
	fi
done

if grep -q "msleep" $1/include/linux/delay.h ; then
	echo "#define BCM_HAS_MSLEEP"
fi

if grep -q "msleep_interruptible" $1/include/linux/delay.h ; then
	echo "#define BCM_HAS_MSLEEP_INTERRUPTIBLE"
fi

if grep -q "skb_copy_from_linear_data" $1/include/linux/skbuff.h ; then
	echo "#define BCM_HAS_SKB_COPY_FROM_LINEAR_DATA"
fi

if grep -q "pci_ioremap_bar" $1/include/linux/pci.h ; then
	echo "#define BCM_HAS_PCI_IOREMAP_BAR"
fi

if grep -q "PCI_DEV_FLAGS_MSI_INTX_DISABLE_BUG" $1/include/linux/pci.h ; then
	echo "#define BCM_HAS_INTX_MSI_WORKAROUND"
fi

if grep -q "pci_target_state" $1/include/linux/pci.h ; then
	echo "#define BCM_HAS_PCI_TARGET_STATE"
fi

if grep -q "pci_choose_state" $1/include/linux/pci.h ; then
	echo "#define BCM_HAS_PCI_CHOOSE_STATE"
fi

if grep -q "pci_pme_capable" $1/include/linux/pci.h ; then
	echo "#define BCM_HAS_PCI_PME_CAPABLE"
fi

if grep -q "pci_enable_wake" $1/include/linux/pci.h ; then
	echo "#define BCM_HAS_PCI_ENABLE_WAKE"
fi

if grep -q "pci_set_power_state" $1/include/linux/pci.h ; then
	echo "#define BCM_HAS_PCI_SET_POWER_STATE"
fi

if [ -e "$1/include/linux/pm_wakeup.h" ]; then
	TGT_H="$1/include/linux/pm_wakeup.h"
elif [ -e "$1/include/linux/pm.h" ]; then
	TGT_H="$1/include/linux/pm.h"
fi

if [ -n "$TGT_H" ]; then
	if grep -q "device_can_wakeup"        $TGT_H && \
	   grep -q "device_may_wakeup"        $TGT_H && \
	   grep -q "device_set_wakeup_enable" $TGT_H ; then
		echo "#define BCM_HAS_DEVICE_WAKEUP_API"
	fi
fi

if [ -f $1/include/asm-generic/pci-dma-compat.h ]; then
	TGT_H=$1/include/asm-generic/pci-dma-compat.h
	num_args=`awk '/pci_dma_mapping_error/,/[;{]/ {printf $0; next}' $TGT_H | awk -F ',' '{print NF}'`
	if [ $num_args -eq 2 ]; then
		echo "#define BCM_HAS_NEW_PCI_DMA_MAPPING_ERROR"
	elif grep -q "pci_dma_mapping_error" $TGT_H ; then
		echo "#define BCM_HAS_PCI_DMA_MAPPING_ERROR"
	fi
fi

if grep -q "pcie_set_readrq" $1/include/linux/pci.h ; then
	echo "#define BCM_HAS_PCIE_SET_READRQ"
fi

if grep -q "print_mac" $1/include/linux/if_ether.h ; then
	echo "#define BCM_HAS_PRINT_MAC"
fi

# ethtool_op_set_tx_ipv6_csum() first appears in linux-2.6.23
if grep -q "ethtool_op_set_tx_ipv6_csum" $1/include/linux/ethtool.h ; then
	echo "#define BCM_HAS_ETHTOOL_OP_SET_TX_IPV6_CSUM"
fi

# ethtool_op_set_tx_hw_csum() first appears in linux-2.6.12
if grep -q "ethtool_op_set_tx_hw_csum" $1/include/linux/ethtool.h ; then
	echo "#define BCM_HAS_ETHTOOL_OP_SET_TX_HW_CSUM"
fi

# set_tx_csum first appears in linux-2.4.23
if grep -q "(*set_tx_csum)" $1/include/linux/ethtool.h ; then
	echo "#define BCM_HAS_SET_TX_CSUM"
fi

if grep -q "skb_transport_offset" $1/include/linux/skbuff.h ; then
	echo "#define BCM_HAS_SKB_TRANSPORT_OFFSET"
fi

if grep -q "skb_dma_map" $1/include/linux/skbuff.h ; then
	echo "#define BCM_HAS_SKB_DMA_MAP"
fi

if grep -q "ip_hdr" $1/include/linux/ip.h ; then
	echo "#define BCM_HAS_IP_HDR"
fi

if grep -q "ip_hdrlen" $1/include/net/ip.h ; then
	echo "#define BCM_HAS_IP_HDRLEN"
fi

if grep -q "tcp_hdr" $1/include/linux/tcp.h ; then
	echo "#define BCM_HAS_TCP_HDR"
fi

if grep -q "tcp_optlen" $1/include/linux/tcp.h ; then
	echo "#define BCM_HAS_TCP_OPTLEN"
fi

TGT_H=$1/include/linux/netdevice.h
if grep -q "struct netdev_queue" $TGT_H ; then
	echo "#define BCM_HAS_STRUCT_NETDEV_QUEUE"
else
	num_args=`awk '/ netif_rx_complete\(struct/,/\)/ {printf $0; next}' $TGT_H | awk -F ',' '{print NF}'`
	if [ -n "$num_args" -a $num_args -eq 2 ]; then
		# Define covers netif_rx_complete, netif_rx_schedule,
		# __netif_rx_schedule, and netif_rx_schedule_prep
		echo "#define BCM_HAS_NEW_NETIF_INTERFACE"
	fi
fi

if grep -q "napi_gro_receive" $TGT_H ; then
	echo "#define BCM_HAS_NAPI_GRO_RECEIVE"
fi

if grep -q "netif_tx_lock" $TGT_H ; then
	echo "#define BCM_HAS_NETIF_TX_LOCK"
fi

if grep -q "vlan_gro_receive" $1/include/linux/if_vlan.h ; then
	echo "#define BCM_HAS_VLAN_GRO_RECEIVE"
fi

if [ -f $1/include/linux/device.h ]; then
	if grep -q "dev_name" $1/include/linux/device.h ; then
		echo "#define BCM_HAS_DEV_NAME"
	fi
fi

if [ -f $1/include/linux/mii.h ]; then
	if grep -q "mii_resolve_flowctrl_fdx" $1/include/linux/mii.h ; then
		echo "#define BCM_HAS_MII_RESOLVE_FLOWCTRL_FDX"
	fi
fi

if [ -f $1/include/linux/phy.h ]; then
	if grep -q "mdiobus_alloc" $1/include/linux/phy.h ; then
		echo "#define BCM_HAS_MDIOBUS_ALLOC"
	fi

	if grep -q "struct device *parent" $1/include/linux/phy.h ; then
		echo "#define BCM_MDIOBUS_HAS_PARENT"
	fi
fi

if [ -f $1/include/linux/dma-mapping.h ]; then
	if grep -q "dma_data_direction" $1/include/linux/dma-mapping.h ; then
		echo "#define BCM_HAS_DMA_DATA_DIRECTION"
	fi
fi
