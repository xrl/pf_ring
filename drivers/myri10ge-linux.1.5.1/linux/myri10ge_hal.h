#ifndef _MYRI10GE_HAL_H_
#define _MYRI10GE_HAL_H_

/* make sure linux/version.h is included here since it might be
 * removed from myri10ge.c one day */
#include <linux/version.h>

#ifdef __VMKERNEL_MODULE__
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,17)
#define ESX3 1
#include "skb_funcs.h"
#include "esx3_compat.h"
#else
#define ESX4 1
#include "esx4_compat.h"
#endif /* LINUX_VERSION_CODE */
#include "myri10ge_netq.h"
#endif /* __VMKERNEL_MODULE__ */

#include "myri10ge_version.h"
#include "myri10ge_checks.h"

#ifdef MYRI10GE_HAVE_IPV6_CHECKSUM_H
#include <net/ip6_checksum.h>
#endif

#ifndef __iomem
#define __iomem
#endif

#ifndef __force
#define __force
#endif

#ifndef __unused
#define __unused __attribute__ ((unused))
#endif

#ifndef PCI_CAP_ID_VNDR
#define PCI_CAP_ID_VNDR 0x9
#endif

#ifndef PCI_CAP_ID_EXP
#define PCI_CAP_ID_EXP 0x10
#endif

#ifndef PCI_EXP_DEVCTL
#define PCI_EXP_DEVCTL 0x8
#endif

#ifndef PCI_EXP_DEVCTL_READRQ
#define PCI_EXP_DEVCTL_READRQ 0x7000
#endif

#ifndef PCI_EXP_LNKSTA
#define PCI_EXP_LNKSTA		18
#endif

#ifndef PCI_EXT_CAP_ID_ERR
#define PCI_EXT_CAP_ID_ERR	1
#endif

#ifndef PCI_ERR_CAP
#define PCI_ERR_CAP 24
#endif

#ifndef PCI_EXP_FLAGS_TYPE
#define PCI_EXP_FLAGS_TYPE 0x00f0
#endif

#ifndef PCI_EXP_TYPE_ROOT_PORT
#define PCI_EXP_TYPE_ROOT_PORT 0x4
#endif

#ifndef PCI_ERR_CAP_ECRC_GENC
#define PCI_ERR_CAP_ECRC_GENC	0x00000020
#endif

#ifndef PCI_ERR_CAP_ECRC_GENE
#define PCI_ERR_CAP_ECRC_GENE	0x00000040
#endif

#ifndef PCI_DEVICE_ID_NVIDIA_NFORCE_CK804_PCIE
#define PCI_DEVICE_ID_NVIDIA_NFORCE_CK804_PCIE 0x005d
#endif

#ifndef PCI_DEVICE_ID_NVIDIA_NFORCE_CK804_ROOT
#define PCI_DEVICE_ID_NVIDIA_NFORCE_CK804_ROOT 0x005e
#endif

#ifndef PCI_DEVICE_ID_NVIDIA_NFORCE_MCP55_PCIE_369
#define PCI_DEVICE_ID_NVIDIA_NFORCE_MCP55_PCIE_369 0x0369
#endif

#ifndef PCI_DEVICE_ID_NVIDIA_NFORCE_MCP55_PCIE_374
#define PCI_DEVICE_ID_NVIDIA_NFORCE_MCP55_PCIE_374 0x0374
#endif

#ifndef PCI_DEVICE_ID_NVIDIA_NFORCE_MCP55_PCIE_378
#define PCI_DEVICE_ID_NVIDIA_NFORCE_MCP55_PCIE_378 0x0378
#endif

/* the following PCI id is also defined in myri10ge.c
 * since it must be available in the kernel specific
 * and in this hal header. */
#ifndef PCI_DEVICE_ID_SERVERWORKS_HT2000_PCIE
#define PCI_DEVICE_ID_SERVERWORKS_HT2000_PCIE 0x0132
#endif

#ifndef PCI_DEVICE_ID_INTEL_E5000_PCIE23
#define PCI_DEVICE_ID_INTEL_E5000_PCIE23 0x25f7
#endif

#ifndef PCI_DEVICE_ID_INTEL_E5000_PCIE47
#define PCI_DEVICE_ID_INTEL_E5000_PCIE47 0x25fa
#endif

#ifndef PCI_VENDOR_ID_MYRICOM
#define PCI_VENDOR_ID_MYRICOM	0x14c1
#endif

#ifndef IRQF_SHARED
#define IRQF_SHARED SA_SHIRQ
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0) && !defined module_param
#define module_param(name, type, perm) MODULE_PARM(name, _MX_PARM_##type)
#define _MX_PARM_ulong "l"
#define _MX_PARM_charp "s"
#define _MX_PARM_int "i"
#else
#include <linux/moduleparam.h>
#endif

#ifdef CONFIG_64BIT
static inline void
myri10ge_pio_copy(void __iomem *to, const void *from, size_t size)
{
	register volatile u64 *to64;
	volatile u64 *from64;
	size_t i;

	to64 = (volatile u64 *) to;
	from64 = (volatile u64 *) from;
	for (i = (size / 8); i; i--) {
		__raw_writeq(*from64, to64);
		to64++;
		from64++;
	}
}
#else
static inline void
myri10ge_pio_copy(void __iomem *to, const void *from, size_t size)
{
	register volatile u32 *to32;
	const volatile u32 *from32;
	size_t i;

	to32 = (volatile u32 *) to;
	from32 = (volatile u32 *) from;
	for (i = (size / 4); i; i--) {
		__raw_writel(*from32, to32);
		to32++;
		from32++;
	}
}
#endif

#ifndef MYRI10GE_HAVE_PM_MESSAGE_T
#define pm_message_t u32
#define pci_choose_state(pdev,pm) (pm)
#endif

#ifdef MYRI10GE_HAVE_PRIVATE_PM_STATE
#define pci_save_state(a) pci_save_state(a, mgp->pm_state)
#define pci_restore_state(a) pci_restore_state(a, mgp->pm_state)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,19)
/* pci_get_bus_and_slot() appeared in 2.6.19 to replace pci_find_slot() deprecated in 2.6.23 */
#define myri10ge_pci_get_bus_and_slot pci_get_bus_and_slot
#define myri10ge_pci_get_dev_put pci_dev_put
#else
#define myri10ge_pci_get_bus_and_slot pci_find_slot
#define myri10ge_pci_get_dev_put(d) /* nothing */
#endif

/* Rather than using normal pci config space writes, we must map the
 * Nvidia config space ourselves.  This is because on opteron/nvidia
 * class machine the 0x{e,f}000000 mapping is handled by the nvidia
 * chipset, that means the internal PCI device (the on-chip
 * northbridge), or the amd-8131 bridge and things behind them are not
 * visible by this method.
 */

static u32 __iomem *
myri10ge_mmio_ext_config(struct pci_dev *dev, int where)
{
	u32 __iomem *ptr32 = NULL;
	struct pci_dev *mcp55, *ck804;
	unsigned long base = 0UL;
	static unsigned long config_phys = 0;
	u32 pci_id;
	u16 word;
	unsigned long dev_base;

	if (config_phys == 0) {
		if (dev->vendor != PCI_VENDOR_ID_NVIDIA)
			goto unknown;

		if (dev->device == PCI_DEVICE_ID_NVIDIA_NFORCE_CK804_PCIE) {
			ck804 = myri10ge_pci_get_bus_and_slot(0, 0);
			if (ck804) {
				if (ck804->vendor == PCI_VENDOR_ID_NVIDIA &&
				    ck804->device == PCI_DEVICE_ID_NVIDIA_NFORCE_CK804_ROOT) {
					pci_read_config_word(ck804, 0x90, &word);
					base = ((unsigned long)word & 0xfff) << 28;
				}
				myri10ge_pci_get_dev_put(ck804);
			}
		} else if (dev->device >= PCI_DEVICE_ID_NVIDIA_NFORCE_MCP55_PCIE_374 &&
			   dev->device <= PCI_DEVICE_ID_NVIDIA_NFORCE_MCP55_PCIE_378) {
			mcp55 = myri10ge_pci_get_bus_and_slot(0, 0);
			if (mcp55) {
				if (mcp55->vendor == PCI_VENDOR_ID_NVIDIA &&
				    mcp55->device == PCI_DEVICE_ID_NVIDIA_NFORCE_MCP55_PCIE_369) {
					pci_read_config_word(mcp55, 0x90, &word);
					base = ((unsigned long)word & 0x7ffeU) << 25;
				}
				myri10ge_pci_get_dev_put(mcp55);
			}
		} else {
			goto unknown;
		}
		if (!base)
			return NULL;
		dev_base = (base 
			    + (unsigned long)dev->bus->number * 0x00100000UL
			    + (unsigned long)dev->devfn * 0x00001000UL);
		ptr32 = (uint32_t *) ioremap(dev_base, 4);
		if (!ptr32)
			return NULL;

		pci_id = *ptr32;
		iounmap(ptr32);
		if (pci_id != dev->vendor + (dev->device << 16)) {
			printk("Ext-conf-space at unknown address, contact help@myri.com\n");
			return NULL;
		}
		config_phys = base;
	}


	dev_base = (config_phys
		    + (unsigned long)dev->bus->number * 0x00100000UL
		    + (unsigned long)dev->devfn * 0x00001000UL);
	ptr32 = (u32 __iomem *) ioremap(dev_base + where, 4);
	return ptr32;

unknown:
	printk("Ext-conf-space with unknown chipset %x:%x\n",
	       dev->vendor, dev->device);
	printk("contact help@myri.com\n");
	return NULL;
}

static int
myri10ge_read_ext_config_dword(struct pci_dev *dev, int where, u32 *val)
{
	u32 __iomem *ptr32;
	int status = pci_read_config_dword(dev, where, val);
	if (status && (ptr32 = myri10ge_mmio_ext_config(dev, where))) {
		*val = *(u32 __force *)ptr32;
		iounmap(ptr32);
		return 0;
	}
	return status;
}

static int
myri10ge_write_ext_config_dword(struct pci_dev *dev, int where, u32 val)
{
	u32 __iomem *ptr32;
	int status = pci_write_config_dword(dev, where, val);
	if (status &&  (ptr32 = myri10ge_mmio_ext_config(dev, where))) {
		*(u32 __force *) ptr32 = val;
		iounmap(ptr32);
		return 0;
	}
	return status;
}

#undef pci_find_ext_capability /* GPL only */
#define pci_find_ext_capability(dev, cap) 0

#ifdef CONFIG_PCI_MSI
#define MYRI10GE_HAVE_MSI 1
#else
#define myri10ge_try_msi(mgp) 0
#endif

#ifdef DMA_BIT_MASK
/* ignore old DMA_32/64BIT_MASK definitions that are marked as deprecated in 2.6.31 */
#undef DMA_32BIT_MASK
#define DMA_32BIT_MASK DMA_BIT_MASK(32)
#undef DMA_64BIT_MASK
#define DMA_64BIT_MASK DMA_BIT_MASK(64)
#endif

#ifndef	DMA_32BIT_MASK
#define DMA_32BIT_MASK ((dma_addr_t)0xffffffffULL)
#endif

#ifndef	DMA_64BIT_MASK
#define DMA_64BIT_MASK ((dma_addr_t)~0ULL)
#endif

/* do not static inline since gfp_t appeared recently */
#define myri10ge_kzalloc(size, flags)		\
({						\
	void *ret = kmalloc(size, flags);	\
	if (ret)				\
		memset(ret, 0, size);		\
	ret;					\
})

static inline void
myri10ge_msleep(unsigned int msecs)
{
#ifndef __VMKERNEL_MODULE__
	unsigned long timeout = HZ * msecs / 1000 + 1;
	while (timeout) {
		/* schedule_timeout_uninterruptible appeared in 2.6.15 */
		__set_current_state(TASK_UNINTERRUPTIBLE);
		timeout = schedule_timeout(timeout);
	}
#else
	mdelay(msecs*10);
#endif
}

static inline void
myri10ge_pci_set_consistent_dma_mask(struct pci_dev *pdev, u64 mask)
{
	int dont_care; 
#ifdef ESX3	
	dont_care = pci_set_dma_mask(pdev, DMA_64BIT_MASK);
#else
	dont_care = pci_set_consistent_dma_mask(pdev, DMA_64BIT_MASK);
#endif
}

#ifdef MYRI10GE_SKB_LINEARIZE_HAS_GFP
#define myri10ge_skb_linearize(skb) skb_linearize(skb, GFP_ATOMIC)
#else
#define myri10ge_skb_linearize skb_linearize
#endif

#ifdef MYRI10GE_HAVE_SKB_TAIL_POINTER
#define myri10ge_skb_tail_pointer skb_tail_pointer
#else
#define myri10ge_skb_tail_pointer(skb) (skb)->tail 
#endif

#ifdef NETIF_F_GSO_SHIFT
#define myri10ge_skb_is_gso skb_is_gso
#define MYRI10GE_GSO_SIZE gso_size
#ifdef NETIF_F_TSO6
#define myri10ge_skb_is_gso_v6(skb) (skb_shinfo(skb)->gso_type & SKB_GSO_TCPV6)
#else
#define myri10ge_skb_is_gso_v6(skb) (0)
#endif
#else
#define myri10ge_skb_is_gso(skb) skb_shinfo(skb)->tso_size
#define MYRI10GE_GSO_SIZE tso_size
#define myri10ge_skb_is_gso_v6(skb) (0)
#endif

#ifndef ESX4
#ifdef MYRI10GE_SKB_PADTO_RETURNS_SKB
#define myri10ge_skb_padto(skb, len)	\
({					\
	skb = skb_padto(skb, ETH_ZLEN);	\
	skb == NULL;			\
})
#else /* MYRI10GE_SKB_PADTO_RETURNS_SKB */
#define myri10ge_skb_padto skb_padto
#endif /* MYRI10GE_SKB_PADTO_RETURNS_SKB */
#endif

#ifndef ESX3
#ifdef MYRI10GE_HAVE_NETDEV_ALLOC_SKB
#define myri10ge_netdev_alloc_skb netdev_alloc_skb
#else /* MYRI10GE_HAVE_NETDEV_ALLOC_SKB */
static inline struct sk_buff *
myri10ge_netdev_alloc_skb(struct net_device * dev, unsigned int length)
{
	struct sk_buff * skb = dev_alloc_skb(length);
	if (likely((skb != NULL)))
		skb->dev = dev;
	return skb;
}
#endif /* MYRI10GE_HAVE_NETDEV_ALLOC_SKB */
#endif /* ESX3 */

/* CHECKSUM_HW replaced by CHECKSUM_PARTIAL and CHECKSUM_COMPLETE in 2.6.19 */
#ifndef CHECKSUM_PARTIAL
#define CHECKSUM_PARTIAL CHECKSUM_HW
#endif
#ifndef CHECKSUM_COMPLETE
#define CHECKSUM_COMPLETE CHECKSUM_HW
#endif

/* __GFP_COMP does not exist in some 2.6.5 kernels.
 * Just set it to 0 since we do not use it until 2.6.16 anyway */
#ifndef __GFP_COMP
#define __GFP_COMP 0
#endif

/* __be32 appeared with __bitwise in 2.6.9 */
#ifndef __bitwise
#define __bitwise
typedef u32 __be32;
typedef u16 __be16;
#endif

#define MYRI10GE_ETHTOOL_OPS_TYPE typeof(*((struct net_device *)NULL)->ethtool_ops)

/* 2.6.20 splits skb->csum into an anonymous union csum (type __wsum) and csum_offset (__u32) */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
#define MYRI10GE_SKB_CSUM_OFFSET csum_offset
#else
#define MYRI10GE_SKB_CSUM_OFFSET csum
#endif

/*
 * RHEL4u7 included an LRO version which does not support
 * correct checksum offload on vlan frames, so just ignore
 * it and compile our own version in for any 2.6.9 kernel.
 * 
 */
   
#if LINUX_VERSION_CODE == KERNEL_VERSION(2,6,9)
#undef MYRI10GE_KERNEL_LRO
#define MYRI10GE_KERNEL_LRO 0
#endif

/* GRO depends on NAPI */
#ifndef MYRI10GE_NAPI
#ifdef MYRI10GE_HAVE_GRO_FRAGS
#undef MYRI10GE_HAVE_GRO_FRAGS
#endif /* MYRI10GE_HAVE_GRO_FRAGS */
#ifdef MYRI10GE_HAVE_GRO_SKB
#undef MYRI10GE_HAVE_GRO_SKB
#endif
#endif /* MYRI10GE_NAPI */

/*
 * RHEL5 backported GRO support in an incompatible way
 */
#if defined (MYRI10GE_HAVE_GRO_FRAGS) &&		 	\
	   LINUX_VERSION_CODE == KERNEL_VERSION(2,6,18)
#define RHEL_GRO 1
#endif
/*
 * Safeguard against potential RHEL4 GRO backport
 */
#if defined (MYRI10GE_HAVE_GRO_FRAGS) &&		 	\
	   LINUX_VERSION_CODE == KERNEL_VERSION(2,6,9)
#undef MYRI10GE_HAVE_GRO_FRAGS
#endif
#if defined (MYRI10GE_HAVE_GRO_SKB) &&		 		\
	   LINUX_VERSION_CODE == KERNEL_VERSION(2,6,9)
#undef MYRI10GE_HAVE_GRO_SKB
#endif

#if defined(MYRI10GE_HAVE_GRO_SKB) || defined(MYRI10GE_HAVE_GRO_FRAGS)
#define MYRI10GE_HAVE_GRO
#endif

#if !MYRI10GE_KERNEL_LRO && defined(MYRI10GE_HAVE_WSUM_IN_LRO_H)
#undef MYRI10GE_HAVE_WSUM_IN_LRO_H
#endif

#if !defined(MYRI10GE_HAVE_WSUM) && !defined(MYRI10GE_HAVE_WSUM_IN_LRO_H)
typedef __u32 __bitwise __wsum;
typedef __u16 __bitwise __sum16;
static inline __wsum csum_unfold(__sum16 n) { return (__force __wsum)n; }
#endif

/* include lro.h unconditionally so as to pick up wsum typedefs in RHLE5u3*/
#if MYRI10GE_KERNEL_LRO && defined(MYRI10GE_HAVE_WSUM_IN_LRO_H)
#include <linux/inet_lro.h>
#endif

/* workstruct rework in 2.6.20,
 * work is passed has an argument to the function, mgp is its container */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20) || defined (ESX4)
#define MYRI10GE_INIT_WORK(work, func, arg) INIT_WORK(work, func)
#define MYRI10GE_WATCHDOG_ARG_TYPE struct work_struct *
#define MYRI10GE_WATCHDOG_ARG_CONTAINER_OF_MGP(ptr, type, member) container_of(ptr, type, member)
#else
#define MYRI10GE_INIT_WORK(work, func, arg) INIT_WORK(work, func, arg)
#define MYRI10GE_WATCHDOG_ARG_TYPE void *
#define MYRI10GE_WATCHDOG_ARG_CONTAINER_OF_MGP(ptr, type, member) ptr
#endif

/* tcp_v4_check lost its tcp header argument in 2.6.21 in
 * kernel.org and 2.6.20 in FC7; just use csum_tcpudp_magic for simplicity */
#define myri10ge_tcp_v4_check(th, len, saddr, daddr, base) csum_tcpudp_magic(saddr, daddr, len, IPPROTO_TCP, base)

#ifndef IA32_MSR_CR_PAT
#define IA32_MSR_CR_PAT 0x277
#endif

#if (defined(CONFIG_X86) || defined (CONFIG_X86_64)) && !defined(__VMKERNEL_MODULE__)
#ifdef MYRI10GE_HAVE___IOREMAP
#define MYRI10GE_HAVE_PAT 1
#else
#define MYRI10GE_HAVE_PAT 0
#endif /* MYRI10GE_HAVE___IOREMAP */
#else
#define MYRI10GE_HAVE_PAT 0
#endif

/* skb->h got renamed in 2.6.22, use the corresponding macros then */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
#define myri10ge_skb_transport_offset skb_transport_offset
#define myri10ge_tcp_hdrlen tcp_hdrlen
#define myri10ge_skb_transport_header skb_transport_header
#define myri10ge_ip_hdr ip_hdr
#define myri10ge_ipv6_hdr ipv6_hdr
#else
static inline int myri10ge_skb_transport_offset(const struct sk_buff *skb) { return skb->h.raw - skb->data; }
static inline unsigned int myri10ge_tcp_hdrlen(const struct sk_buff *skb) { return skb->h.th->doff * 4; }
#define myri10ge_skb_transport_header(skb) ((skb)->h.raw)
#define myri10ge_ip_hdr(skb) ((skb)->nh.iph)
#define myri10ge_ipv6_hdr(skb) ((skb)->nh.ipv6h)
#endif

static inline void myri10ge_skb_copy_to_linear_data(struct sk_buff *skb,
						    const void *from,
						    const unsigned int len)
{
	memcpy(skb->data, from, len);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
#define myri10ge_is_power_of_2 is_power_of_2
#else
static inline
int myri10ge_is_power_of_2(unsigned long n)
{
        return (n != 0 && ((n & (n - 1)) == 0));
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,23)
#define myri10ge_pcie_get_readrq pcie_get_readrq
#define myri10ge_pcie_set_readrq pcie_set_readrq
#else
static inline int
myri10ge_pcie_get_readrq(struct pci_dev *pdev)
{
	int ret, cap;
	u16 ctl;

	cap = pci_find_capability(pdev, PCI_CAP_ID_EXP);
	if (!cap)
		return -EINVAL;

	ret = pci_read_config_word(pdev, cap + PCI_EXP_DEVCTL, &ctl);
	if (!ret)
		ret = 128 << ((ctl & PCI_EXP_DEVCTL_READRQ) >> 12);

	return ret;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
static inline int
myri10ge_ffs(int mask)
{
	int bit;
	if (!mask)
		return 0;
	for (bit = 0; bit <= 8 * sizeof(mask); bit++) {
		if (((mask >> bit) & 1) == 1) {
			return bit+1;
		}
	}
}
#else
#define myri10ge_ffs ffs
#endif

static inline int
myri10ge_pcie_set_readrq(struct pci_dev *pdev, int rq)
{
	int cap, err = -EINVAL;
	u16 ctl, v;

	if (rq < 128 || rq > 4096 || (rq & (rq-1)))
		goto out;

	v = (myri10ge_ffs(rq) - 8) << 12;

	cap = pci_find_capability(pdev, PCI_CAP_ID_EXP);
	if (!cap)
		goto out;

	err = pci_read_config_word(pdev, cap + PCI_EXP_DEVCTL, &ctl);
	if (err)
		goto out;

	if ((ctl & PCI_EXP_DEVCTL_READRQ) != v) {
		ctl &= ~PCI_EXP_DEVCTL_READRQ;
		ctl |= v;
		err = pci_write_config_word(pdev, cap + PCI_EXP_DEVCTL, ctl);
	}

out:
	return err;
}
#endif

#if defined (ESX4) && defined (CONFIG_MTRR)
/* ESX4 advertises CONFIG_MTRR, yet does not export mtrr_add/del */
#undef CONFIG_MTRR
#endif

#ifndef __VMKERNEL_MODULE__
#define myri10ge_register_netdev register_netdev
#define myri10ge_netq_query_all(mgp)
#endif

#ifndef ESX3
#define MYRI10GE_NONATOMIC_SLEEP_MS 15
#define DECLARE_INIT_DEV(x,i) struct device *x = i
#define myri10ge_dev_kfree_skb_any dev_kfree_skb_any
#define myri10ge_alloc_page alloc_page
#define myri10ge_alloc_pages alloc_pages
#define myri10ge_reduce_truesize(S,L) (S)->truesize -= (L)
#define myri10ge_set_truesize(S,L) (S)->truesize = (L)
#define myri10ge_scan_fw_version sscanf
#define myri10ge_pci_map_skb_data(DEV, SKB, LEN, FLAG) \
	pci_map_single(DEV, SKB->data, LEN, FLAG)
#define myri10ge_inc_intrcnt(dev)
#define myri10ge_inc_intrcnt(dev)
#else
#define MYRI10GE_NONATOMIC_SLEEP_MS 30
#define DECLARE_INIT_DEV(x,i) void *x
#define myri10ge_dev_kfree_skb_any dev_kfree_skb
#define myri10ge_alloc_page(F) __get_free_pages(F,0)
#define myri10ge_alloc_pages(F,O) __get_free_pages(F,O)
#define myri10ge_reduce_truesize(S,L) do {} while (0)
#define myri10ge_set_truesize(S,L) do {} while (0)
#define myri10ge_pci_map_skb_data(DEV, SKB, LEN, FLAG) ((SKB)->headMA)
#define myri10ge_inc_intrcnt(dev) vmk_net_inc_dev_intrcount(dev)
#define vmknetddi_queueops_invalidate_state(dev)
#endif

#ifdef __VMKERNEL_MODULE__
#define MYRI10GE_DFLT_MAX_SLICES (4)
#define MYRI10GE_DFLT_MSI (1)
#define myri10ge_report_queue(SKB, QID) \
 do { \
	 vmknetddi_queueops_set_skb_queueid (SKB,VMKNETDDI_QUEUEOPS_MK_RX_QUEUEID((QID)));} while (0)
#else /* !__VMKERNEL_MODULE__*/

#define MYRI10GE_DFLT_MAX_SLICES (1)
#define MYRI10GE_DFLT_MSI (-1)
#ifdef MYRI10GE_HAVE_MULTI_TX
#define myri10ge_report_queue(SKB, QID) skb_set_queue_mapping((SKB), (QID))
#else
#define myri10ge_report_queue(SKB, QID)
#endif
#endif /* __VMKERNEL_MODULE__ */


#define MYRI10GE_MAC_FMT "%s"
#define MYRI10GE_DECLARE_MAC_BUF(var) char var[18]
char *myri10ge_print_mac(char *buf, const u8 *addr)
{
	sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
		addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
	return buf;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
#define MYRI10GE_HAVE_SSET_COUNT
#endif

#ifdef MYRI10GE_HAVE_NEW_NAPI
#ifdef MYRI10GE_HAVE_NETIF_RX_WITH_NETDEV
#define myri10ge_netif_rx_schedule(dev,napi) netif_rx_schedule(dev,napi)
#define myri10ge_netif_rx_complete(dev,napi) netif_rx_complete(dev,napi)
#else
#define myri10ge_netif_rx_schedule(dev,napi) napi_schedule(napi)
#define myri10ge_netif_rx_complete(dev,napi) napi_complete(napi)
#endif
#define myri10ge_napi_enable(ss) napi_enable(&((ss)->napi))
#define myri10ge_napi_disable(ss) napi_disable(&((ss)->napi))
#define myri10ge_netif_napi_add(netdev,napi,_poll,_weight) netif_napi_add(netdev,napi,_poll,_weight)
#define NETDEV_TO_MGP(netdev) netdev_priv(netdev)
#else
#define myri10ge_netif_rx_schedule(dev,napi) netif_rx_schedule(dev)
#define myri10ge_napi_enable(ss) netif_poll_enable((ss)->dev)
#define myri10ge_napi_disable(ss) netif_poll_disable((ss)->dev)
#define myri10ge_netif_napi_add(netdev,napi,_poll,_weight) do { netdev->poll = _poll; netdev->weight = _weight; } while (0)
#define NETDEV_TO_MGP(netdev) ((struct myri10ge_slice_state *)netdev->priv)->mgp
#endif

/* 
 *  Old kernels have bugs which can cause problems dealing
 *  with non-linear frames in oddball codepaths.  To work
 *  around this, we linearize everything but IP and IPv6.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18)
#define myri10ge_linearize_non_ip(skb) 0
#else
/* ensure that NAPI is enabled so that we are not called in an irq
 * context, and skb_linearize() will work on HIGHMEM kernels
 */
#if !defined(MYRI10GE_NAPI) && defined(CONFIG_HIGHMEM)
#if MYRI10GE_RX_SKBS
#warning Use of myri10ge_rx_skbs=0 will be disallowed
#else
#error You must enable MYRI10GE_NAPI on HIGHMEM kernels < 2.6.18 so that skb_linearize can be used safely
#endif /* MYRI10GE_RX_SKBS */
#endif /* !defined(MYRI10GE_NAPI) && defined(CONFIG_HIGHMEM) */


#ifndef ETH_P_OMX
#define ETH_P_OMX 0x86DF
#endif

static inline int
myri10ge_linearize_non_ip(struct sk_buff *skb)
{
  struct vlan_hdr *vh = (struct vlan_hdr *) (skb->data);

  /* linearize anything but IP or IPv6 */
  if (skb->protocol != htons(ETH_P_IP) &&
      skb->protocol != htons(ETH_P_IPV6) &&
      skb->protocol != htons(ETH_P_OMX) &&
      !(skb->protocol == htons(ETH_P_8021Q) &&
	(vh->h_vlan_encapsulated_proto == htons(ETH_P_IP) ||
	 vh->h_vlan_encapsulated_proto == htons(ETH_P_IPV6) ||
	 vh->h_vlan_encapsulated_proto == htons(ETH_P_OMX)))) {
    return (myri10ge_skb_linearize(skb));
  }
  return 0;
}

#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18) */

#ifndef NET_IP_ALIGN
#define NET_IP_ALIGN 2
#endif

#ifndef __VMKERNEL_MODULE__
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
#undef ALIGN
#define ALIGN(a, b) (((long)(a) + (b) - 1) & ~(long)((b) - 1))
#define dev_err(a,...) printk(KERN_ERR "myri10ge:" __VA_ARGS__)
#define dev_info(a,...) printk(KERN_INFO "myri10ge:" __VA_ARGS__)
#define dev_warn(a,...) printk(KERN_INFO "myri10ge:" __VA_ARGS__)
#define strlcpy(dst,src,sz) strncpy(dst,src,(sz) - 1)
struct device {
  struct pci_dev pdev;
};
#ifndef NETIF_F_TSO
#define NETIF_F_TSO 0
#define MYRI10GE_HAVE_TSO 0
#else
#define MYRI10GE_HAVE_TSO 1
#endif


#ifndef DMA_BIDIRECTIONAL
#define DMA_BIDIRECTIONAL 0
#endif

#undef MYRI10GE_GSO_SIZE

#ifndef MODULE_VERSION
#define MODULE_VERSION(ver_str)
#endif

#define to_pci_dev(dev) (pdev)
#define dma_alloc_coherent(dev,sz,dma,gfp) \
	pci_alloc_consistent(to_pci_dev(dev),(sz),(dma))
#define dma_free_coherent(dev,sz,addr,dma_addr) \
	pci_free_consistent(to_pci_dev(dev),(sz),(addr),(dma_addr))

#define dma_map_sg(dev,a,b,c) \
	pci_map_sg(to_pci_dev(dev),(a),(b),(c))
#define dma_unmap_sg(dev,a,b,c) \
	pci_unmap_sg(to_pci_dev(dev),(a),(b),(c))

#define dma_map_single(dev,a,b,c) \
	pci_map_single(to_pci_dev(dev),(a),(b),(c))
#define dma_unmap_single(dev,a,b,c) \
	pci_unmap_single(to_pci_dev(dev),(a),(b),(c))

#define dma_mapping_error(addr) (0)

#ifndef CONFIG_FW_LOADER
#define request_firmware(a,b,c) -ENOENT
#define release_firmware(a)
struct firmware {
  size_t size;
  u8 *data;
};
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,23)
typedef void irqreturn_t;
#define IRQ_NONE
#define IRQ_HANDLED
#define IRQ_RETVAL(x)
#endif

#ifndef PCI_DEVICE
#define PCI_DEVICE(vend,dev) \
        .vendor = (vend), .device = (dev), \
        .subvendor = PCI_ANY_ID, .subdevice = PCI_ANY_ID
#endif

#ifndef HAVE_NETDEV_PRIV
#define netdev_priv(dev) ((dev)->priv)
#endif

#undef myri10ge_skb_is_gso
#define myri10ge_skb_is_gso(a) 0

struct work_struct {
  int dummy;
};
#define INIT_WORK(a0,a1,a2)
#define schedule_work(a)
#define flush_scheduled_work()

#undef MYRI10GE_HAVE_PAT
#define MYRI10GE_HAVE_PAT 0

#define num_online_cpus() 1
#undef DECLARE_INIT_DEV
#define DECLARE_INIT_DEV(x,i) char *x __attribute__ ((unused)) = "myri10ge";
#define MYRI10GE_HAVE_IRQ_HANDLER_REGS 1
#else
#define MYRI10GE_HAVE_TSO 1

#endif /* 2.4.x */
#endif /* ESX3 */
#ifndef MYRI10GE_HAVE_TSO
#define MYRI10GE_HAVE_TSO 1
#endif

#ifndef __GFP_NOWARN
#define __GFP_NOWARN 0
#endif

#if (defined CONFIG_DCA || defined CONFIG_DCA_MODULE)
#define MYRI10GE_HAVE_DCA
#if defined (ESX4)
/* just to be different, ESX4 uses different names for
   dca functions.  The *exact same* interfaces are used except
   dca_{un,}register_notify() is not required.
*/
#define dca_get_tag(x) vmklnx_dca_get_tag(x)
#define dca_remove_requester(x) vmklnx_dca_remove_requester(x)
#define dca_add_requester(x) vmklnx_dca_add_requester(x)
#endif /* ESX4 */

#include <linux/dca.h>
#if defined (ESX4)
inline void dca_register_notify(struct notifier_block *arg) {}
#define dca_unregister_notify(x)
#endif /* ESX4 */
#endif

#if MYRI10GE_LRO
#if MYRI10GE_KERNEL_LRO &&  (defined CONFIG_INET_LRO || defined CONFIG_INET_LRO_MODULE)
#include <linux/inet_lro.h>
#ifndef LRO_F_VLAN_CSUM_FIXUP
#define LRO_F_VLAN_CSUM_FIXUP 0
#endif
#else
#undef EXPORT_SYMBOL
#define EXPORT_SYMBOL(x)  /* prevent LRO exports from being exported */
#include <net/dsfield.h>
#include "inet_lro.c"
#endif
#include <net/ip.h>
#include <net/tcp.h>
#endif

#if defined(CONFIG_SYSFS) && defined(__ATTR)
#define MYRI10GE_HAVE_SYSFS
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
#define MYRI10GE_MSIX_RESTORE_BUGFIX

#ifndef PCI_CAP_ID_MSIX
#define PCI_CAP_ID_MSIX 0x11
#endif

#ifndef PCI_MSIX_ENTRY_SIZE
#define PCI_MSIX_ENTRY_SIZE 16
#endif
#ifndef PCI_MSIX_FLAGS_QSIZE
#define PCI_MSIX_FLAGS_QSIZE 0x7ff
#endif
#endif

#ifndef MYRI10GE_HAVE_IOREMAP_WC
#define ioremap_wc ioremap
#endif

#ifndef MYRI10GE_HAVE_MULTI_TX
#define netdev_queue net_device
#define netdev_get_tx_queue(x, y) (x)
#define netif_tx_queue_stopped netif_queue_stopped
#define netif_tx_start_queue netif_start_queue
#define netif_tx_stop_queue netif_stop_queue
#define netif_tx_wake_queue netif_wake_queue
#define netif_tx_start_all_queues netif_start_queue
#define netif_tx_stop_all_queues netif_stop_queue
#define netif_tx_wake_all_queues netif_wake_queue
#define MYRI10GE_GET_NUM_TXQ(x) (1)
#define MYRI10GE_SET_NUM_TXQ(x,y)
#else
#ifndef __VMKERNEL_MODULE__
#define MYRI10GE_HAVE_TOEPLITZ_MULTI_TX 1
#endif
#define MYRI10GE_GET_NUM_TXQ(dev) (dev->real_num_tx_queues)
#define MYRI10GE_SET_NUM_TXQ(dev,y) (dev->real_num_tx_queues = y)
#endif /* MYRI10GE_HAVE_MULTI_TX */

#ifndef MYRI10GE_HAVE_SKB_GET_QUEUE_MAPPNG
#define skb_get_queue_mapping(x) 0
#endif /* MYRI10GE_HAVE_SKB_GET_QUEUE_MAPPNG */

#ifndef MYRI10GE_HAVE_ALLOC_ETHERDEV_MQ
#define alloc_etherdev_mq(x, y) alloc_etherdev(x)
#endif /* MYRI10GE_HAVE_ALLOC_ETHERDEV_MQ */

#ifndef MYRI10GE_HAVE_MMIOWB
#define myri10ge_mmiowb()
#else
#define myri10ge_mmiowb() mmiowb()
#endif

#include <linux/if.h>
#ifdef IFF_MASTER_ARPMON
#define myri10ge_set_last_rx(dev, jiffies) do { /* nothing */ } while (0)
#else
#define myri10ge_set_last_rx(dev, jiffies) do { (dev)->last_rx = jiffies; } while (0)
#endif

#ifdef MYRI10GE_HAVE_SKB_RECORD_RX_QUEUE
#define myri10ge_skb_record_rx_queue skb_record_rx_queue
#else
#define myri10ge_skb_record_rx_queue(s,q)
#endif

/* DMA_BIT_MASK() added in 2.6.30 */
#ifndef DMA_32BIT_MASK
#define DMA_32BIT_MASK DMA_BIT_MASK(32)
#endif
#ifndef DMA_64BIT_MASK
#define DMA_64BIT_MASK DMA_BIT_MASK(64)
#endif

#ifndef NETIF_F_LRO
#define NETIF_F_LRO 32768
#endif

#ifndef MYRI10GE_HAVE_SET_FLAGS
#define ETH_FLAG_LRO (1 << 15)
#endif

#ifdef MYRI10GE_NEED_TRANS_START_UPDATE
#define myri10ge_set_trans_start(dev, jiffies) do { (dev)->trans_start = jiffies; } while (0)
#else
#define myri10ge_set_trans_start(dev, jiffies) do { /* nothing */ } while (0)
#endif

#ifdef MYRI10GE_HAVE_TOEPLITZ_MULTI_TX
#ifdef __VMKERNEL_MODULE__
#define myri10ge_update_select_queue(dev, func) do { /* nothing */ } while (0)
#elif defined MYRI10GE_HAVE_NET_DEVICE_OPS
static const struct net_device_ops myri10ge_netdev_ops_mtxq;
static const struct net_device_ops myri10ge_netdev_ops;
#define myri10ge_update_select_queue(dev, func) do { \
		dev->netdev_ops = (func == NULL ? &myri10ge_netdev_ops :\
				   &myri10ge_netdev_ops_mtxq); } while (0)
#else
#define myri10ge_update_select_queue(dev, func) do {dev->select_queue = func; } while (0);
#endif /* __VMKERNEL_MODULE__ */
#else
#define myri10ge_update_select_queue(dev, func) do { /* nothing */ } while (0)
#endif /* MYRI10GE_HAVE_TOEPLITZ_MULTI_TX */

#ifndef MYRI10GE_HAVE_NETDEV_TX_T
typedef int netdev_tx_t;
#ifndef NETDEV_TX_BUSY
#define NETDEV_TX_BUSY 1
#endif
#ifndef NETDEV_TX_OK
#define NETDEV_TX_OK 1
#endif
#endif

#endif /* _MYRI10GE_HAL_H_ */
