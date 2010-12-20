/***********************************************************************
 * This software may be used and distributed according to the terms of
 * the GNU General Public License (GPL), incorporated herein by reference.
 * Drivers based on or derived from this code fall under the GPL and must
 * retain the authorship, copyright and license notice.  This file is not
 * a complete program and may only be used when the entire operating
 * system is licensed under the GPL.
 * See the file COPYING in this distribution for more information.
 ************************************************************************/
#ifndef VXGE_KCOMPAT_H
#define VXGE_KCOMPAT_H

/* From 2.6.37 onwards, VLAN_GROUP_ARRAY_LEN is renamed to VLAN_N_VID */
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,36))
#if !defined VLAN_N_VID
#define VLAN_N_VID VLAN_GROUP_ARRAY_LEN
#endif
#endif

/* From 2.6.34 kernel onwards HAVE_NETDEV_POLL is removed and
 * NAPI is enabled by default
 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31))
#define VXGE_NETDEV_POLL
#else
#ifdef HAVE_NETDEV_POLL
#define VXGE_NETDEV_POLL
#endif
#endif

#if (!defined(VXGE_USE_FW_HEADER_FILE) && \
		(defined(CONFIG_FW_LOADER) || defined(CONFIG_FW_LOADER_MODULE)))
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,17))
#define VXGE_KERNEL_FW_UPGRADE
#endif
#endif

#ifndef CHECKSUM_PARTIAL
#define CHECKSUM_PARTIAL CHECKSUM_HW
#endif

#ifndef DMA_BIT_MASK
#define DMA_BIT_MASK(n) (((n) == 64) ? ~0ULL : ((1ULL<<(n))-1))
#endif

#ifndef IRQ_RETVAL
typedef void irqreturn_t;
#define IRQ_NONE
#define IRQ_HANDLED
#define IRQ_RETVAL(x)
#endif

#ifndef  PCI_MSIX_FLAGS_QSIZE
#define  PCI_MSIX_FLAGS_QSIZE   0x7FF
#endif

#ifndef gfp_t
#define gfp_t	int
#endif

#ifndef ETH_FCS_LEN
#define ETH_FCS_LEN	4
#endif

#ifndef PCI_CAP_ID_EXP
#define PCI_CAP_ID_EXP	0x10
#endif

#ifndef PCI_EXP_LNKSTA
#define PCI_EXP_LNKSTA	18
#endif

#ifndef PCI_MSIX_FLAGS
#define	PCI_MSIX_FLAGS		2
#endif

#ifndef PCI_CAP_ID_MSIX
#define PCI_CAP_ID_MSIX		0x11
#endif

#ifndef PCI_MSIX_FLAGS_ENABLE
#define PCI_MSIX_FLAGS_ENABLE	0x8000
#endif

#ifndef NETDEV_TX_OK
#define NETDEV_TX_OK	0
#endif

#ifndef NETDEV_TX_BUSY
#define NETDEV_TX_BUSY	1
#endif

#ifndef NETDEV_TX_LOCKED
#define NETDEV_TX_LOCKED	-1
#endif

#ifndef SET_NETDEV_DEV
#define SET_NETDEV_DEV(net, pdev)
#endif

#ifndef HAVE_FREE_NETDEV
#define free_netdev(x)  kfree(x)
#endif

#ifndef module_param
#define VXGE_MODULE_PARAM_INT(p, val) \
	static int p = val; \
	MODULE_PARM(p, "i");
#endif

#ifndef SKB_GSO_UDP
#define SKB_GSO_UDP	0x2
#endif

#ifndef SKB_GSO_TCPV4
#define SKB_GSO_TCPV4 	0x1
#endif

#ifndef SKB_GSO_TCPV6
#define SKB_GSO_TCPV6	0x10
#endif

#ifndef NETIF_F_GSO
#define gso_size tso_size
#endif

#ifndef SET_ETHTOOL_OPS
#define SPEED_10000			10000
#define SUPPORTED_10000baseT_Full	(1 << 12)
#define ADVERTISED_10000baseT_Full	(1 << 12)
#endif

#ifndef	strlcpy
#define strlcpy vxge_strlcpy
static inline size_t vxge_strlcpy(char *dest, const char *src, size_t size)
{
	size_t ret = strlen(src);

	if (size) {
		size_t len = (ret >= size) ? size - 1 : ret;
		memcpy(dest, src, len);
		dest[len] = '\0';
	}
	return ret;
}
#endif

#ifdef INIT_QUEUE
#define schedule_work schedule_task
#define flush_schedule_work fluch_scheduled_tasks
#define INIT_WORK_IN_PROGRESS
#endif

#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2, 4, 22) )
#define pci_name(x)     ((x)->slot_name)
#endif /* < 2.4.22 */

#if (LINUX_VERSION_CODE <= 0x020600)
#define schedule_work(x)    schedule_task(x)
#define INIT_WORK(x, y, z)  INIT_TQUEUE(x, y, z)
#endif

#if (( LINUX_VERSION_CODE < KERNEL_VERSION(2, 4, 27) ) || \
	(( LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 0) ) && \
	( LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 3) )))
#define netdev_priv(x) x->priv
#endif

#ifndef  spin_trylock_irqsave
#define spin_trylock_irqsave(lock, flags) \
({ \
	local_irq_save(flags); \
	spin_trylock(lock) ? \
	1 : ({ local_irq_restore(flags); 0; }); \
})
#endif

#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0) )
#undef pci_register_driver
#define pci_register_driver pci_module_init

#define list_for_each_entry_safe(pos, n, head, member) \
	for (pos = list_entry((head)->next, typeof(*pos), member), \
		n = list_entry(pos->member.next, typeof(*pos), member); \
		&pos->member != (head); \
		pos = n, n = list_entry(n->member.next, typeof(*n), member))

#endif /* < 2.5.0 */

/* synchronize_irq */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 28))

#define vxge_synchronize_irq(x)		synchronize_irq()

#define flush_scheduled_work		flush_scheduled_tasks
#else
#define vxge_synchronize_irq(x)		synchronize_irq(x)
#endif /* < 2,5,28 */

#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 5) )
#define pci_dma_sync_single_for_cpu	pci_dma_sync_single
#define pci_dma_sync_single_for_device	pci_dma_sync_single_for_cpu
#endif /* < 2.6.5 */

#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 8) )

#define msleep(x)	do { set_current_state(TASK_UNINTERRUPTIBLE); \
				schedule_timeout((x * HZ)/1000 + 2); \
			} while (0)

#endif /* < 2.6.8 */

#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 9))

#define __iomem

#ifndef __be32
#define __be32 u32
#endif

#define msleep_interruptible(x) do {set_current_state(TASK_INTERRUPTIBLE); \
				schedule_timeout((x * HZ)/1000); \
			} while(0)
#endif /* < 2.6.9 */

#ifndef is_broadcast_ether_addr
#define is_broadcast_ether_addr vxge_is_broadcast_ether_addr
static inline int vxge_is_broadcast_ether_addr(const u8 *addr)
{
	return (addr[0] & addr[1] & addr[2] & addr[3] & addr[4] & addr[5])
		== 0xff;
}
#endif

#ifndef is_multicast_ether_addr
#define is_multicast_ether_addr vxge_is_multicast_ether_addr
static inline int vxge_is_multicast_ether_addr(const u8 *addr)
{
	return (0x01 & addr[0]);
}
#endif

#ifndef pci_msix_table_size
#define pci_msix_table_size _vxge_pci_msix_table_size

#define msi_control_reg(base)           (base + PCI_MSI_FLAGS)
#define msix_table_size(control)        ((control & PCI_MSIX_FLAGS_QSIZE)+1)

/**
 * _vxge_pci_msix_table_size - return the number of device's MSI-X table entries
 * @dev: pointer to the pci_dev data structure of MSI-X device function
 */
static inline int _vxge_pci_msix_table_size(struct pci_dev *dev)
{
	int pos;
	u16 control;

	pos = pci_find_capability(dev, PCI_CAP_ID_MSIX);
	if (!pos)
		return 0;

	pci_read_config_word(dev, msi_control_reg(pos), &control);
	return msix_table_size(control);
}
#endif

#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 14) )

#ifndef kzalloc
#define kzalloc _vxge_kzalloc
static inline void * _vxge_kzalloc(size_t size, int flags)
{
	void *ret = kmalloc(size, flags);
	if (ret)
		memset(ret, 0, size);
	return ret;

}
#endif

#endif /* < 2.6.14 */

#if (LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 15))
#undef CONFIG_PM
#endif /* < 2.6.15 */

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24))
#define VXGE_NAPI_ENABLE(napi) napi_enable(napi)
#define VXGE_NAPI_DISABLE(napi) napi_disable(napi)
#else
#define VXGE_NAPI_ENABLE(napi)
#define VXGE_NAPI_DISABLE(napi)
#endif 

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 18))
#ifndef netdev_alloc_skb
#define netdev_alloc_skb _vxge_netdev_alloc_skb
static inline struct sk_buff *_vxge_netdev_alloc_skb(struct net_device *dev,
					unsigned int length)
{
	/* 16 == NET_PAD_SKB */
	struct sk_buff *skb;
	skb = alloc_skb(length + 16, GFP_ATOMIC);
	if (likely(skb != NULL)) {
		skb_reserve(skb, 16);
		skb->dev = dev;
	}
	return skb;
}
#endif

#ifndef IRQF_SHARED
#define IRQF_SHARED SA_SHIRQ
#endif

#ifndef skb_is_gso
#ifdef NETIF_F_TSO
#define skb_is_gso _vxge_skb_is_gso
static inline int _vxge_skb_is_gso(const struct sk_buff *skb)
{
	return skb_shinfo(skb)->gso_size;
}
#else
#define skb_is_gso(a) 0
#endif
#endif

#endif /* < 2.6.18 */

#ifdef NETIF_F_TSO
#ifdef NETIF_F_TSO6
#define is_tso_enabled(dev) ((dev->features & NETIF_F_TSO) || \
			 (dev->features & NETIF_F_TSO6))
#else
#define is_tso_enabled(dev) (dev->features & NETIF_F_TSO)
#endif
#else
#define is_tso_enabled(dev)
#endif

/* netif_set_gso_max_size is defined from 2.6.26 onwards.
 * In ESX this function is not supported 
 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 26) \
		&& (!(defined(__VMKERNEL_MODULE__))))
#define VXGE_GSO_MAX_SIZE	TRUE
#else
#define VXGE_GSO_MAX_SIZE	FALSE
#endif

static inline void
vxge_netif_set_gso_max_size(struct net_device *dev, int gso_size)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 26))
        netif_set_gso_max_size(dev, gso_size);
#else
#endif
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 21))
#define VXGE_CHECK_PCI_CHANNEL_OFFLINE(pdev) { \
	if (pci_channel_offline(pdev)) \
		return IRQ_NONE; \
}
#else
#define VXGE_CHECK_PCI_CHANNEL_OFFLINE(pdev)
#endif /* > 2.6.21 */

#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 22) )
#define ip_hdr(skb) (skb->nh.iph)
#endif /* < 2.6.22 */

#if ((defined(VXGE_KERNEL_FW_UPGRADE)))
#define vxge_release_firmware(x)	release_firmware(x);
#else
#define vxge_release_firmware(x)
#endif

#ifndef netdev_for_each_mc_addr
#define netdev_for_each_mc_addr(mclist, dev) \
	for (mclist = dev->mc_list; mclist; mclist = mclist->next)
#endif

static inline int vxge_netdev_mc_count(struct net_device *dev)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34))
	return netdev_mc_count(dev);
#else
	return dev->mc_count;
#endif
}

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 26))
#define vxge_fifo_trylock(fifo)	__netif_tx_trylock(fifo->txq)
#define vxge_fifo_unlock(fifo) __netif_tx_unlock(fifo->txq)
#else
#define VXGE_LLTX
#define vxge_fifo_trylock(fifo)	spin_trylock(&fifo->tx_lock)
#define vxge_fifo_unlock(fifo) spin_unlock(&fifo->tx_lock)
#endif /* LLTX */

static inline void vxge_netif_do_rx_complete(struct net_device *dev,
				void *napi)
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24))
	netif_rx_complete(dev);
#elif (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29))
	netif_rx_complete(dev, (struct napi_struct *) napi);
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29))
	napi_complete((struct napi_struct *) napi);
#endif 
}
static inline int vxge_netif_subqueue_stopped(struct net_device *dev,
                        struct sk_buff *skb, u16 queue_index)
{
	int ret = 0;
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 23))
#ifdef CONFIG_NETDEVICES_MULTIQUEUE
	ret = netif_subqueue_stopped(dev, queue_index);
#endif
#else
	ret = netif_subqueue_stopped(dev, skb);
#endif
	return ret;
}

#if !defined(ESX_KL)
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 23))
#define alloc_etherdev_mq(size, no_of_vpath)	alloc_etherdev(size)
#endif /* < 2.6.23 */
#endif 

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27))
#define vxge_tx_queues_set(dev, count) (ndev->real_num_tx_queues = no_of_vpath)
#else
#define vxge_tx_queues_set(dev, count)
#endif /* > 2.6.30 */

static inline void __iomem *vxge_pci_ioremap_bar(struct pci_dev *pdev, int bar)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 28))
	return pci_ioremap_bar(pdev, bar);
#else
	return	ioremap(pci_resource_start(pdev, bar),
			pci_resource_len(pdev, bar));
#endif /* >= 2.6.28 */
}

static inline void vxge_netif_do_rx_schedule(struct net_device *dev, void *napi)
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24))
	netif_rx_schedule(dev);
#elif (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29))
	netif_rx_schedule(dev, (struct napi_struct *) napi);
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29))
	napi_schedule((struct napi_struct *) napi);
#endif 
}

extern irqreturn_t vxge_do_isr_napi(int irq, void *dev_id);

#if (LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 19))
static inline irqreturn_t vxge_isr_napi(int irq, void *dev_id,
						struct pt_regs *regs)
#else
static inline irqreturn_t vxge_isr_napi(int irq, void *dev_id)
#endif 
{

	return vxge_do_isr_napi(irq, dev_id);

}

extern irqreturn_t vxge_do_isr(int irq, void *dev_id);
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 19))
static inline irqreturn_t vxge_isr(int irq, void *dev_id, struct pt_regs *regs)
#else
static inline irqreturn_t vxge_isr(int irq, void *dev_id)
#endif 
{
	return vxge_do_isr(irq, dev_id);
}

extern irqreturn_t vxge_do_rx_msix_handle(int irq, void *dev_id);
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 19))
static inline irqreturn_t vxge_rx_msix_handle(int irq, void *dev_id,
						struct pt_regs *regs)
#else
static inline irqreturn_t vxge_rx_msix_handle(int irq, void *dev_id)
#endif 
{
	return vxge_do_rx_msix_handle(irq, dev_id);
}

extern irqreturn_t vxge_do_tx_msix_handle(int irq, void *dev_id);
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 19))
static inline irqreturn_t vxge_tx_msix_handle(int irq, void *dev_id,
						struct pt_regs *regs)
#else
static inline irqreturn_t vxge_tx_msix_handle(int irq, void *dev_id)
#endif 
{
	return vxge_do_tx_msix_handle(irq, dev_id);
}

extern irqreturn_t vxge_do_rx_msix_napi_handle(int irq, void *dev_id);
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 19))
static inline irqreturn_t vxge_rx_msix_napi_handle(int irq, void *dev_id,
						struct pt_regs *regs)
#else
static inline irqreturn_t vxge_rx_msix_napi_handle(int irq, void *dev_id)
#endif 
{
	return vxge_do_rx_msix_napi_handle(irq, dev_id);
}

extern irqreturn_t vxge_do_alarm_msix_handle(int irq, void *dev_id);
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 19))
static inline irqreturn_t vxge_alarm_msix_handle(int irq, void *dev_id,
							struct pt_regs *regs)
#else
static inline irqreturn_t vxge_alarm_msix_handle(int irq, void *dev_id)
#endif 
{
	return vxge_do_alarm_msix_handle(irq, dev_id);
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 21))
#define vlan_group_get_device(vg, id) (vg->vlan_devices[id])
#define vlan_group_set_device(vg, id, dev) if (vg) vg->vlan_devices[id] = dev;
#endif

#ifndef IN_MULTICAST
#define IN_MULTICAST(a) ((((long int) (a)) & 0xf0000000) == 0xe0000000)
#endif

#ifndef INADDR_BROADCAST
#define INADDR_BROADCAST	((unsigned long int) 0xffffffff)
#endif

static inline dma_addr_t vxge_dma_map(struct pci_dev *pdev,
				void *vaddr, size_t size, int dir)
{

	return pci_map_single(pdev, vaddr, size, dir);

}

static inline void vxge_dma_unmap(struct pci_dev *pdev,
			dma_addr_t dma_addr, size_t size, int dir)
{

	pci_unmap_single(pdev, dma_addr, size, dir);

}

#if (LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 20))
#define vxge_pci_find_device(_a, _b, _c) \
	pci_find_device(_a, _b, _c)
#else
#define vxge_pci_find_device(_a, _b, _c) \
	pci_get_device(_a, _b, _c)
#endif

#ifdef VXGE_SNMP
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24))
#define proc_net        init_net.proc_net
#endif
#endif /* SNMP */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 10)
#ifndef	mmiowb
#define mmiowb()	barrier()
#endif
#endif

#ifndef do_div
#define do_div(n, base) ({ \
int __res; \
__res = ((unsigned long) n) % (unsigned) base; \
n = ((unsigned long) n) / (unsigned) base; \
__res; })
#endif

#endif
