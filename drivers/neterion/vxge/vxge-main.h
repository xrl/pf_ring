/***********************************************************************
 * This software may be used and distributed according to the terms of
 * the GNU General Public License (GPL), incorporated herein by reference.
 * Drivers based on or derived from this code fall under the GPL and must
 * retain the authorship, copyright and license notice.  This file is not
 * a complete program and may only be used when the entire operating
 * system is licensed under the GPL.
 * See the file COPYING in this distribution for more information.
 ************************************************************************/
/******************************************************************************
 * vxge-main.h: Driver for Neterion Inc's X3100 Series 10GbE PCIe I/O
 *              Virtualized Server Adapter.
 * Copyright(c) 2002-2010 Exar Corp.
 ******************************************************************************/
#ifndef VXGE_MAIN_H
#define VXGE_MAIN_H
#include "vxge-traffic.h"
#include "vxge-config.h"
#include "vxge-version.h"
#include "vxge-manage.h"
#include <linux/list.h>
#define VXGE_DRIVER_NAME		"vxge"
#define VXGE_DRIVER_VENDOR		"Neterion, Inc"
#define VXGE_DRIVER_VERSION_MAJOR 0

#define DRV_VERSION	VXGE_VERSION_MAJOR"."VXGE_VERSION_MINOR"."\
	VXGE_VERSION_FIX"."VXGE_VERSION_BUILD"-"\
	VXGE_VERSION_FOR

#ifndef PCI_VENDOR_ID_S2IO
#define PCI_VENDOR_ID_S2IO			0x17D5
#endif

#ifndef PCI_DEVICE_ID_TITAN_WIN
#define PCI_DEVICE_ID_TITAN_WIN		0x5733
#endif

#ifndef PCI_DEVICE_ID_TITAN_UNI
#define PCI_DEVICE_ID_TITAN_UNI		0x5833
#endif

#define VXGE_HW_TITAN1_PCI_REVISION	1
#define	VXGE_HW_TITAN1A_PCI_REVISION	2

#define	VXGE_HP_ISS_SUBSYS_VENDORID		0x103C
#define	VXGE_HP_ISS_SUBSYS_DEVICEID_1	0x323B
#define	VXGE_HP_ISS_SUBSYS_DEVICEID_2	0x323C

#define	VXGE_USE_DEFAULT		0xffffffff
#define VXGE_HW_SVLAN_ID_DEFAULT	0xffffffff
#define VXGE_HW_VPATH_MSIX_ACTIVE	4
#define VXGE_ALARM_MSIX_ID		2
#define VXGE_HW_RXSYNC_FREQ_CNT		4
#define VXGE_LL_WATCH_DOG_TIMEOUT	(15 * HZ)
#define VXGE_LL_RX_COPY_THRESHOLD	256
#define VXGE_DEF_FIFO_LENGTH		84

#define NO_STEERING			0
#define PORT_STEERING		0x1
#define RTH_TCP_UDP_STEERING	0x2
#define RTH_IPV4_STEERING	0x3
#define RTH_IPV6_EX_STEERING	0x4
#define RTH_BUCKET_SIZE		8

#define	TX_PRIORITY_STEERING	1
#define	TX_VLAN_STEERING		2
#define	TX_PORT_STEERING		3
#define	TX_MULTIQ_STEERING		4

#define FLOW_CTRL_DISABLE		0
#define FLOW_CTRL_ENABLE		1
#define FLOW_CTRL_ENABLE_HIGH_PRIO_FUNC	2

#define VXGE_HW_PROM_MODE_ENABLE	1
#define VXGE_HW_PROM_MODE_DISABLE	0

#define VXGE_HW_FW_UPGRADE_DISABLE	0
#define VXGE_HW_FW_UPGRADE_ALL		1
#define VXGE_HW_FW_UPGRADE_FORCE	2
#define VXGE_HW_FW_UPGRADE_WO_PXE_FORCE	3
#define VXGE_HW_FUNC_MODE_DISABLE	0

#define VXGE_TTI_BTIMER_VAL 250000
#define VXGE_T1A_TTI_LTIMER_VAL 80
#define VXGE_T1A_TTI_RTIMER_VAL 	0
#define VXGE_T1A_TTI_RTIMER_PRI0_VAL	0
#define VXGE_T1A_TTI_RTIMER_PRI1_VAL	100  
#define VXGE_T1A_TTI_RTIMER_PRI2_VAL	200  
#define VXGE_T1A_TTI_RTIMER_PRI3_VAL	400  

#define VXGE_TTI_LTIMER_VAL 1000
#define VXGE_TTI_RTIMER_VAL 0
#define VXGE_TTI_RTIMER_ADAPT_VAL 10
#define VXGE_RTI_BTIMER_DEFAULT_VAL	1000
#define VXGE_RTI_BTIMER_VAL (250  << 4)
#define VXGE_RTI_BTIMER_WATCHDOG_VAL	100000
#define VXGE_RTI_LTIMER_VAL 100
#define VXGE_RTI_RTIMER_VAL 0
#define VXGE_RTI_RTIMER_ADAPT_VAL 15
#define VXGE_FIFO_INDICATE_MAX_PKTS VXGE_DEF_FIFO_LENGTH
#define VXGE_ISR_POLLING_CNT 	8
#define VXGE_MAX_CONFIG_DEV	0xFF
#define VXGE_EXEC_MODE_DISABLE	0
#define VXGE_EXEC_MODE_ENABLE	1
#define VXGE_MAX_CONFIG_PORT	1

#define VXGE_ALL_VID_DISABLE	0
#define VXGE_ALL_VID_ENABLE	1
#define VXGE_PAUSE_CTRL_DISABLE	0
#define VXGE_PAUSE_CTRL_ENABLE	1
#define VXGE_DISABLE_LOW_LATENCY_CONF	0
#define VXGE_ENABLE_LOW_LATENCY_CONF	1

#define TTI_TX_URANGE_A	5
#define TTI_TX_URANGE_B	15
#define TTI_TX_URANGE_C	40
#define TTI_TX_UFC_A	5
#define TTI_TX_UFC_B	40
#define TTI_TX_UFC_C	60
#define TTI_TX_UFC_D	100
#define TTI_T1A_TX_UFC_A	30
#define TTI_T1A_TX_UFC_B	80

#define PRIORITY_0	0
#define PRIORITY_1	1
#define PRIORITY_2	2
#define PRIORITY_3	3

#define NAPI_WEIGHT_0	96
#define NAPI_WEIGHT_1	64
#define NAPI_WEIGHT_2	32
#define NAPI_WEIGHT_3	16

#define TTI_TX_UFC_A_0	5
#define TTI_TX_UFC_B_0	40
#define TTI_TX_UFC_C_0	60
#define TTI_TX_UFC_D_0	100

#define TTI_TX_UFC_A_1	5
#define TTI_TX_UFC_B_1	40
#define TTI_TX_UFC_C_1	70
#define TTI_TX_UFC_D_1	100

#define TTI_TX_UFC_A_2	10
#define TTI_TX_UFC_B_2	45
#define TTI_TX_UFC_C_2	80
#define TTI_TX_UFC_D_2	100

#define TTI_TX_UFC_A_3	10
#define TTI_TX_UFC_B_3	45
#define TTI_TX_UFC_C_3	80
#define TTI_TX_UFC_D_3	100

/* Slope - (max_mtu - min_mtu)/(max_mtu_ufc - min_mtu_ufc) */
/* Slope - 93 */
/* 60 - 9k Mtu, 140 - 1.5k mtu */
#define TTI_T1A_TX_UFC_C(mtu)	(60 + ((VXGE_HW_MAX_MTU - mtu)/93))

/* Slope - 37 */
/* 100 - 9k Mtu, 300 - 1.5k mtu */
#define TTI_T1A_TX_UFC_D(mtu)	(100 + ((VXGE_HW_MAX_MTU - mtu)/37))

#define RTI_RX_URANGE_A		5
#define RTI_RX_URANGE_B		15
#define RTI_RX_URANGE_C		40
#define RTI_T1A_RX_URANGE_A	1
#define RTI_T1A_RX_URANGE_B	20
#define RTI_T1A_RX_URANGE_C	50
#define RTI_RX_UFC_A		1
#define RTI_RX_UFC_B		5
#define RTI_RX_UFC_C		10
#define RTI_RX_UFC_D		15
#define RTI_T1A_RX_UFC_B	20
#define RTI_T1A_RX_UFC_C	50
#define RTI_T1A_RX_UFC_D	60

#define RTI_RX_UFC_A_0	1
#define RTI_RX_UFC_B_0	20
#define RTI_RX_UFC_C_0	50
#define RTI_RX_UFC_D_0	60

#define RTI_RX_UFC_A_1	1
#define RTI_RX_UFC_B_1	30
#define RTI_RX_UFC_C_1	60
#define RTI_RX_UFC_D_1	70

#define RTI_RX_UFC_A_2	1
#define RTI_RX_UFC_B_2	40
#define RTI_RX_UFC_C_2	70
#define RTI_RX_UFC_D_2	80

#define RTI_RX_UFC_A_3	1
#define RTI_RX_UFC_B_3	50
#define RTI_RX_UFC_C_3	80
#define RTI_RX_UFC_D_3	90

/*
 * The interrupt rate is maintained at 3k per second with the moderation
 * parameters for most traffic but not all. This is the maximum interrupt
 * count allowed per function with INTA or per vector in the case of
 * MSI-X in a 10 millisecond time period. Enabled only for Titan 1A.
 */
#define VXGE_T1A_MAX_INTERRUPT_COUNT	100
#define VXGE_T1A_MAX_TX_INTERRUPT_COUNT	200

#define VXGE_ENABLE_NAPI	1
#define VXGE_DISABLE_NAPI	0
#define VXGE_LRO_MAX_BYTES 0x4000
#define VXGE_T1A_LRO_MAX_BYTES 0xC000

#define VXGE_HW_MIN_VPATH_ID_TX_BW_SUPPORT 0
#define VXGE_HW_MAX_VPATH_ID_TX_BW_SUPPORT 7

/* Milli secs timer period */
#define VXGE_TIMER_DELAY		6000

#define VXGE_TIMER_COUNT    	(2 * 60)

#define VXGE_LL_MAX_FRAME_SIZE(size) (size + VXGE_HW_MAC_HEADER_MAX_SIZE)
/*
 * default the size of buffers allocated for dumping stats/buffers
 * These are allocated via vmalloc and include the preformatting
 * thats returned by the HW layer
 */
#define VXGE_MRPCIM_STATS_BUFSIZE       65000
#define VXGE_VPATH_STATS_BUFSIZE        (32 * 1024)
#define VXGE_DEVCONF_BUFSIZE            (32 * 2048)
#define VXGE_REG_DUMP_BUFSIZE           65000

#define is_titan1(dev_id, rev) (((dev_id == PCI_DEVICE_ID_TITAN_UNI) || \
        (dev_id == PCI_DEVICE_ID_TITAN_WIN)) && \
        (rev == VXGE_HW_TITAN1_PCI_REVISION))

#define is_sriov(function_mode) \
	((function_mode == VXGE_HW_FUNCTION_MODE_SRIOV) || \
	(function_mode == VXGE_HW_FUNCTION_MODE_SRIOV_8) || \
	(function_mode == VXGE_HW_FUNCTION_MODE_SRIOV_4))

#define is_mf(function_mode) \
	((function_mode == VXGE_HW_FUNCTION_MODE_MULTI_FUNCTION) || \
	(function_mode == VXGE_HW_FUNCTION_MODE_MULTI_FUNCTION_17) || \
	(function_mode == VXGE_HW_FUNCTION_MODE_MULTI_FUNCTION_2) || \
	(function_mode == VXGE_HW_FUNCTION_MODE_MULTI_FUNCTION_DIRECT_IO) || \
	(function_mode == VXGE_HW_FUNCTION_MODE_MULTI_FUNCTION_4))

#define is_sf(function_mode) \
	(function_mode == VXGE_HW_FUNCTION_MODE_SINGLE_FUNCTION)

enum vxge_reset_event {
	/* reset events */
	VXGE_LL_VPATH_RESET	= 0,
	VXGE_LL_DEVICE_RESET	= 1,
	VXGE_LL_FULL_RESET	= 2,
	VXGE_LL_START_RESET	= 3,
	VXGE_LL_COMPL_RESET	= 4
};
/* These flags represent the devices temporary state */
enum vxge_device_state_t {
__VXGE_STATE_RESET_CARD = 0,
__VXGE_STATE_CARD_UP
};

struct vxge_drv_pmd_info {
	u8 bus_no;
	u8 dev_no;
	u8 read_pmd_info;
};

struct vxge_drv_config {
	int config_dev_cnt;
	int total_dev_cnt;
	unsigned int vpath_per_dev;
};

/* Per vpath data structure */
struct vlanList {
	unsigned int vpath_no;
	unsigned int vlanid_cnt;
	u64 vlanids[4096]; /* The hw supports 4K VIDs per vpath */
};

/* Length of the addl strings that are needed
   for the preformatted buffers */

#define VXGE_STR_DEV_MAC	sizeof("VP :  MAC ADDR - ")
#define VXGE_STR_DEV_VLAN	sizeof("VP :  VLAN - ")

/* The util program stringises the arguments and passes
 * it to the sysfs code.
 */
#define VXGE_MAX_SYSFS_STR		32

struct vxge_config {
	int		tx_pause_enable;
	int		rx_pause_enable;
	int		napi_enable;
#define OLD_NAPI_WEIGHT 32
#define NEW_NAPI_WEIGHT 64
	int		napi_weight;
	int		lro_enable;
	int		aggr_ack;
#define MIN_LRO_PACKETS 1
#define MAX_LRO_PACKETS 10
#define MAX_T1A_LRO_PACKETS	30
	int		lro_max_aggr_per_sess;
	int		lro_max_bytes;
	int		intr_type;
#define INTA	0
#define MSI	1
#define MSI_X	2

	int		ack_aggr;
	int		promisc_en;
	int		promisc_all_en;
#define DISABLE_ADDR_LEARNING	0
#define ENABLE_ADDR_LEARNING	1
	int		addr_learn_en;
	int		rec_all_vid;

	u32		rth_algorithm : 2,
			rth_hash_type_tcpipv4 : 1,
			rth_hash_type_ipv4 : 1,
			rth_hash_type_tcpipv6 : 1,
			rth_hash_type_ipv6 : 1,
			rth_hash_type_tcpipv6ex : 1,
			rth_hash_type_ipv6ex : 1,
			rth_bkt_sz : 8;
	int		rth_jhash_golden_ratio;
	int		tx_steering_type;
	int		rx_steering_type;
	int 		fifo_indicate_max_pkts;
	int		catch_basin_mode;
#define	VXGE_CATCH_BASIN_MODE_ALWAYS_DISABLE	0
#define	VXGE_CATCH_BASIN_MODE_ALWAYS_ENABLE	1
#define	VXGE_CATCH_BASIN_MODE_ALWAYS_DYNAMIC	2

	struct vxge_hw_device_hw_info device_hw_info;
};

struct vxge_msix_entry {
	/* Mimicing the msix_entry struct of Kernel. */
	u16 vector;
	u16 entry;
	u16 in_use;
	void *arg;
};

/* Software Statistics */

struct vxge_sw_stats {
	/* Network Stats (interface stats) */
	struct net_device_stats net_stats;

	/* Virtual Path */
	u64 vpaths_open;
	u64 vpath_open_fail;

	/* Misc. */
	u64 link_up;
	u64 link_down;
};

struct vxge_mac_addrs {
	struct list_head item;
	u64 macaddr;
	u64 macmask;
	u64 credits;
	enum vxge_hw_vpath_mac_addr_origin origin;
	unsigned send_to_nw;
};

struct vxgedev;

struct vxge_fifo_stats {
	u64 tx_frms;
	u64 tx_frms_prev;
	u64 tx_errors;
	u64 tx_bytes;
	u64 tx_bytes_prev;
	u64 txd_not_free;
	u64 txd_out_of_desc;
	u64 pci_map_fail;
};

struct vxge_fifo {
	struct net_device *ndev;
	struct pci_dev *pdev;
	struct __vxge_hw_fifo *handle;
	volatile unsigned long tx_napi_cnt;
#if ((LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 26)) && \
	defined(CONFIG_NETDEVICES_MULTIQUEUE))
	/* The vpath id maintained in the driver -
	 * 0 to 'maximum_vpaths_in_function - 1'
	 */
	int driver_id;
#endif
#if defined(VXGE_LLTX)
	spinlock_t tx_lock;
#else
	struct netdev_queue *txq;
#endif /* LLTX */
	int tx_steering_type;
	int indicate_max_pkts;
	u64 avg_pkt_len;

	int adaptive_intr_coalescing;
	/* Adaptive interrupt moderation parameters used in T1A */
	unsigned long interrupt_count;
	unsigned long jiffies;

	/* flag used to maintain queue state when MULTIQ is not enabled */
#define VPATH_QUEUE_START       0
#define VPATH_QUEUE_STOP        1
	int queue_state;

	int tx_vector_no;
	/* Tx stats */
	struct vxge_fifo_stats stats;
} ____cacheline_aligned;

struct vxge_ring_stats {
	u64 prev_rx_frms;
	u64 rx_frms;
	u64 rx_errors;
	u64 rx_dropped;
	u64 rx_bytes;
	u64 rx_mcast;
	u64 pci_map_fail;
	u64 skb_alloc_fail;
};

struct vxge_ring {
	struct net_device	*ndev;
	struct pci_dev		*pdev;
	struct __vxge_hw_ring	*handle;
	/* The vpath id maintained in the driver -
	 * 0 to 'maximum_vpaths_in_function - 1'
	 */
	int driver_id;

#define VXGE_ADAPTIVE_INTR_COALESCING_OFF	0
#define VXGE_ADAPTIVE_INTR_COALESCING_ON	1
	int adaptive_intr_coalescing;
	/* Adaptive interrupt moderation parameters used in T1A */
	unsigned long interrupt_count;
	unsigned long jiffies;
	int rti_ci;

	 /* copy of the flag indicating whether rx_csum is to be used */
	u32 rx_csum:1;
	volatile unsigned long  rx_napi_cnt;

	int pkts_processed;
	int budget;
	int lro_enable;
	int aggr_ack;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24))
	struct napi_struct napi;
	struct napi_struct *napi_p;
#else
	/* Adding dummy variable to avoid compilation error */
	int napi;
	int pkts_to_process;
#endif 
	int napi_enable;
	int intr_type;

#define VXGE_DEF_MAC_ADDR_COUNT		30
#define VXGE_MAX_MAC_ADDR_COUNT		512

	int rx_vlan_stripped;
	struct vlan_group *vlgrp;
	int rx_vector_no;
	enum vxge_hw_status last_status;
	u32	promisc_en;

	/* Rx stats */
	struct vxge_ring_stats stats;
} ____cacheline_aligned;

struct vxge_vpath {
	struct vxge_fifo fifo;
	struct vxge_ring ring;

	struct __vxge_hw_vpath_handle *handle;

	/* Actual vpath id for this vpath in the device - 0 to 16 */
	int device_id;
	int max_mac_addr_cnt;
	int is_configured;
	int is_open;
	struct vxgedev *vdev;
	u8 (macaddr)[ETH_ALEN];
	u8 (macmask)[ETH_ALEN];

#define VXGE_MAX_LEARN_MAC_ADDR_CNT	2048
	/* mac addresses currently programmed into NIC */
	u16 mac_addr_cnt;
	u16 mcast_addr_cnt;

	struct list_head mac_addr_list;

	u32 level_err;
	u32 level_trace;
};
#define VXGE_COPY_DEBUG_INFO_TO_LL(vdev, err, trace) {	\
	for (i = 0; i < vdev->no_of_vpath; i++) {		\
		vdev->vpaths[i].level_err = err;		\
		vdev->vpaths[i].level_trace = trace;		\
	}							\
	vdev->level_err = err;					\
	vdev->level_trace = trace;				\
}

struct vxgedev {
	struct net_device	*ndev;
	struct pci_dev		*pdev;
	struct __vxge_hw_device *devh;
	u8			titan1;
	struct vlan_group	*vlgrp;
	int vlan_tag_strip;
	struct vxge_config	config;
	unsigned long	state;

	/* Indicates which vpath to reset */
	unsigned long  vp_reset;

	/* Timer used for polling vpath resets */
	struct timer_list vp_reset_timer;

	/* Timer used for polling vpath lockup */
	struct timer_list vp_lockup_timer;

	/*
	 * Flags to track whether device is in All Multicast
	 * or in promiscuous mode.
	 */
	u16		all_multi_flg;
	u16		prev_promisc_flg;
	u64 		prev_l2_switch;

	 /* A flag indicating whether rx_csum is to be used or not. */
	u32	rx_csum:1,
		rx_hwts:1;

	struct vxge_msix_entry *vxge_entries;
	struct msix_entry *entries;
	/*
	 * 4 for each vpath * 17;
	 * total is 68
	 */
#define	VXGE_MAX_REQUESTED_MSIX	68
/* Each msix_table entry is 16 bytes */
#define	VXGE_MSIX_TABLE_SIZE	(16 * VXGE_MAX_REQUESTED_MSIX)
#define VXGE_INTR_STRLEN 80
	char desc[VXGE_MAX_REQUESTED_MSIX][VXGE_INTR_STRLEN];

	enum vxge_hw_event cric_err_event;

	int no_of_vpath;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24))
	struct napi_struct napi;
#else
	/* Flag to indicate if all vpaths are masked */
	int rx_mask_done;
	/* Adding dummy variable to avoid compilation error */
	int napi;
#endif 

	spinlock_t addr_learn_lock; /* address learn serialization lock */

	/* A debug option, when enabled and if error condition occurs,
	 * the driver will do following steps:
	 * - mask all interrupts
	 * - Not clear the source of the alarm
	 * - gracefully stop all I/O
	 * A diagnostic dump of register and stats at this point
	 * reveals very useful information.
	 */
	int exec_mode;
	struct vxge_vpath	*vpaths;

	struct __vxge_hw_vpath_handle *vp_handles[VXGE_HW_MAX_VIRTUAL_PATHS];
	void __iomem *bar0;
	struct vxge_sw_stats	stats;
	int		mtu;
	int     timer_cnt;
	u8 	catch_basin_mode;
	int	orig_gso_max_sz;

	/* Below variables are used for vpath selection to transmit a packet */
	u8 		vpath_selector[VXGE_HW_MAX_VIRTUAL_PATHS];
	u64		vpaths_deployed;
	u32 		intr_cnt;
	u32 		level_err;
	u32 		level_trace;
	char		fw_version[VXGE_HW_FW_STRLEN];

	u32	priv_fun_num;
	u32	num_functions;
	u64	max_rx_buffer_size;

#ifdef INIT_TQUEUE
	struct tq_struct reset_task;
	struct tq_struct svid_update_task;
	struct tq_struct gso_update_task;
#else
	struct work_struct reset_task;
	struct work_struct svid_update_task;
	struct work_struct gso_update_task;
#endif
	u32 svid_upd_sch_count;
};

struct vxge_rx_priv {
	struct sk_buff		*skb;
	unsigned char		*skb_data;
	dma_addr_t		data_dma;
	dma_addr_t		data_size;
};

struct vxge_tx_priv {
	struct sk_buff		*skb;
	dma_addr_t		dma_buffers[MAX_SKB_FRAGS+1];
};

#ifdef VXGE_SNMP
#include<linux/proc_fs.h>

#define VXGE_PROC_MIB_DIR       "vxge"
#define VXGE_PROC_BASE_FILE     "base"
#define VXGE_PROC_DEV_FILE      "dev_table"

struct mib_base {
	char   name[32];
	char   version[32];
	char   build_date[32];
	char   speed[32];
	u8     intr_type;
	u8     doorbell;
	u8     lro;
	u8     lro_aggr_packet;
	u8     napi;
	u8     vlan_tag_strip;
	u8     rx_steering;
	u8     tx_steering;
};

struct mib_dev {
	char   name[32];
	u32    index;
	/* pci */
	char   bdf[32];
	u16    vendor_id;
	u16    device_id;
	u8     irq;
	u8     func_mode;
	/* hw */
	u8     access;
	u8     bandwidth;
	u8     vpath_count;
	u8     link_mode;
	u8     active_link;
	char   perm_hw_addr[32];
	u64    tx_intr_count;
	u64    rx_intr_count;
	/* netdev */
	char   curr_hw_addr[32];
	u32    mtu;
	u8     link_state;
	u8     rx_csum;
	u8     tx_csum;
	u8     tso;
	u8     ufo;
	u8     sg;
	/* netdev stats */
	u64    collision;
	u64    multicast;
	u64    rx_bytes;
	u64    rx_packets;
	u64    rx_dropped;
	u64    rx_errors;
	u64    tx_bytes;
	u64    tx_packets;
	u64    tx_dropped;
	u64    tx_errors;
};

static inline struct proc_dir_entry *vxge_proc_entry_check(
		struct proc_dir_entry *parent, const char *name)
{
	int len = strlen(name);
	struct proc_dir_entry *sub = parent->subdir;

	for (; sub; sub = sub->next)
		if ((len == sub->namelen) && !strcmp(sub->name, name))
			break;
	return sub;
}
#endif /* SNMP */

#ifdef CONFIG_PCI_IOV
static inline int is_sriov_initialize(struct pci_dev *pdev) {
	int pos;
	u16 ctrl;
	pos = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_SRIOV);
	if (pos) {
		pci_read_config_word(pdev, pos + PCI_SRIOV_CTRL, &ctrl);
		if (ctrl & PCI_SRIOV_CTRL_VFE)
			return 1;
	}
	return 0;
}
#endif

static inline int is_svlanid_match(struct __vxge_hw_ring *ring_hw, u16 vlan,
			int promisc_en) {

	int match;

	if (promisc_en)
		match = vxge_getbitarray(ring_hw->svlan_id, vlan);
	else
		match = (vlan == ring_hw->s_vid) ? 1 : 0;
	return match;
}

#ifdef VXGE_SELF_TEST
/* The set of tests that are performed on the
 * adapter
 */
enum vxge_self_test {
	VXGE_EEPROM_ACCESS_TEST = 1,
	VXGE_MDIO_PORT0_TEST,
	VXGE_MDIO_PORT1_TEST,
	VXGE_FLASH_TEST,
	VXGE_FRAME_BUFFER_TEST,
	VXGE_CONTEXT_MEM_TEST
};
int vxge_perform_self_test(struct vxgedev *vdev, enum vxge_self_test test);
#endif

u32 vxge_get_num_devices(struct vxgedev *vdev);

enum vxge_hw_status
vxge_get_vpn(struct vxgedev *vdev, int vfid,
	     int *num_vpn, u32 *vplist);

#ifdef module_param
#define VXGE_MODULE_PARAM_INT(p, val) \
	static int p = val; \
	module_param(p, int, 0);
#endif

#define vxge_os_timer(timer, handle, arg, exp) do { \
		init_timer(&timer); \
		timer.function = handle; \
		timer.data = (unsigned long) arg; \
		mod_timer(&timer, (jiffies + exp)); \
	} while (0);

int __devinit vxge_device_register(struct __vxge_hw_device *devh,
				    struct vxge_config *config,
				    int high_dma, int no_of_vpath,
				    struct vxgedev **vdev);

void vxge_device_unregister(struct __vxge_hw_device *devh);

void vxge_vpath_intr_enable(struct vxgedev *vdev, int vp_id);

void vxge_vpath_intr_disable(struct vxgedev *vdev, int vp_id);

void vxge_callback_link_up(struct __vxge_hw_device *devh);

void vxge_callback_link_down(struct __vxge_hw_device *devh);

enum vxge_hw_status vxge_add_mac_addr(struct vxgedev *vdev,
	struct macInfo *mac);

int vxge_mac_list_del(struct vxge_vpath *vpath, struct macInfo *mac);

enum vxge_hw_status
vxge_rx_1b_compl(struct __vxge_hw_ring *ringh, void *dtr,
	u8 t_code, void *userdata);

enum vxge_hw_status
vxge_xmit_compl(struct __vxge_hw_fifo *fifo_hw, void *dtr,
	enum vxge_hw_fifo_tcode t_code, void *userdata,
	struct sk_buff ***skb_ptr, int nr_skbs, int *more);

int vxge_close(struct net_device *dev);

int vxge_open(struct net_device *dev);

void vxge_close_vpaths(struct vxgedev *vdev, int index);

int vxge_open_vpaths(struct vxgedev *vdev);

enum vxge_hw_status vxge_reset_all_vpaths(struct vxgedev *vdev);

void vxge_stop_all_tx_queue(struct vxgedev *vdev);

void vxge_stop_tx_queue(struct vxge_fifo *fifo);

void vxge_start_all_tx_queue(struct vxgedev *vdev);

void vxge_wake_tx_queue(struct vxge_fifo *fifo, struct sk_buff *skb);

enum vxge_hw_status vxge_add_mac_addr(struct vxgedev *vdev,
	struct macInfo *mac);

enum vxge_hw_status vxge_del_mac_addr(struct vxgedev *vdev,
	struct macInfo *mac);

int vxge_mac_list_add(struct vxge_vpath *vpath,
	struct macInfo *mac);

void vxge_free_mac_add_list(struct vxge_vpath *vpath);

int vxge_learn_mac(struct vxgedev *vdev, u8 *mac_header);

void vxge_age_mac(struct vxgedev *vdev);

enum vxge_hw_status vxge_restore_vpath_mac_addr(struct vxge_vpath *vpath);

enum vxge_hw_status vxge_restore_vpath_vid_table(struct vxge_vpath *vpath);

void print_pmd_info(struct vxgedev *vdev);

int do_vxge_close(struct net_device *dev, int do_io);
extern void initialize_ethtool_ops(struct net_device *ndev);
extern int vxge_ethtool(struct net_device *dev, struct ifreq *rq);

/**
 * #define VXGE_DEBUG_INIT: debug for initialization functions
 * #define VXGE_DEBUG_TX	 : debug transmit related functions
 * #define VXGE_DEBUG_RX  : debug recevice related functions
 * #define VXGE_DEBUG_MEM : debug memory module
 * #define VXGE_DEBUG_LOCK: debug locks
 * #define VXGE_DEBUG_SEM : debug semaphore
 * #define VXGE_DEBUG_ENTRYEXIT: debug functions by adding entry exit statements
*/
#define VXGE_DEBUG_INIT		0x00000001
#define VXGE_DEBUG_TX		0x00000002
#define VXGE_DEBUG_RX		0x00000004
#define VXGE_DEBUG_MEM		0x00000008
#define VXGE_DEBUG_LOCK		0x00000010
#define VXGE_DEBUG_SEM		0x00000020
#define VXGE_DEBUG_ENTRYEXIT	0x00000040
#define VXGE_DEBUG_INTR		0x00000080
#define VXGE_DEBUG_LL_CONFIG	0x00000100

/* Debug tracing for VXGE driver */
#ifndef VXGE_DEBUG_MASK
#define VXGE_DEBUG_MASK	0x0
#endif

#if (VXGE_DEBUG_LL_CONFIG & VXGE_DEBUG_MASK)
#define vxge_debug_ll_config(level, fmt, ...) \
	vxge_debug_ll(level, VXGE_DEBUG_LL_CONFIG, fmt, __VA_ARGS__)
#else
#define vxge_debug_ll_config(level, fmt, ...)
#endif

#if (VXGE_DEBUG_INIT & VXGE_DEBUG_MASK)
#define vxge_debug_init(level, fmt, ...) \
	vxge_debug_ll(level, VXGE_DEBUG_INIT, fmt, __VA_ARGS__)
#else
#define vxge_debug_init(level, fmt, ...)
#endif

#if (VXGE_DEBUG_TX & VXGE_DEBUG_MASK)
#define vxge_debug_tx(level, fmt, ...) \
	vxge_debug_ll(level, VXGE_DEBUG_TX, fmt, __VA_ARGS__)
#else
#define vxge_debug_tx(level, fmt, ...)
#endif

#if (VXGE_DEBUG_RX & VXGE_DEBUG_MASK)
#define vxge_debug_rx(level, fmt, ...) \
	vxge_debug_ll(level, VXGE_DEBUG_RX, fmt, __VA_ARGS__)
#else
#define vxge_debug_rx(level, fmt, ...)
#endif

#if (VXGE_DEBUG_MEM & VXGE_DEBUG_MASK)
#define vxge_debug_mem(level, fmt, ...) \
	vxge_debug_ll(level, VXGE_DEBUG_MEM, fmt, __VA_ARGS__)
#else
#define vxge_debug_mem(level, fmt, ...)
#endif

#if (VXGE_DEBUG_ENTRYEXIT & VXGE_DEBUG_MASK)
#define vxge_debug_entryexit(level, fmt, ...) \
	vxge_debug_ll(level, VXGE_DEBUG_ENTRYEXIT, fmt, __VA_ARGS__)
#else
#define vxge_debug_entryexit(level, fmt, ...)
#endif

#if (VXGE_DEBUG_INTR & VXGE_DEBUG_MASK)
#define vxge_debug_intr(level, fmt, ...) \
	vxge_debug_ll(level, VXGE_DEBUG_INTR, fmt, __VA_ARGS__)
#else
#define vxge_debug_intr(level, fmt, ...)
#endif

#define VXGE_DEVICE_DEBUG_LEVEL_SET(level, mask, vdev) {\
	vxge_hw_device_debug_set((struct __vxge_hw_device  *)vdev->devh, \
		level, mask);\
	VXGE_COPY_DEBUG_INFO_TO_LL(vdev, \
		vxge_hw_device_error_level_get((struct __vxge_hw_device  *) \
			vdev->devh), \
		vxge_hw_device_trace_level_get((struct __vxge_hw_device  *) \
			vdev->devh));\
}

#ifndef NETIF_F_GSO
#ifdef  NETIF_F_UFO
#define vxge_udp_mss(skb) skb_shinfo(skb)->ufo_size
#else
#define vxge_udp_mss(skb) 0
#endif
#else
#define vxge_udp_mss(skb) skb_shinfo(skb)->gso_size
#endif

static inline int vxge_offload_type(struct sk_buff *skb)
{
#ifdef NETIF_F_GSO
	return skb_shinfo(skb)->gso_type;
#else
#ifdef NETIF_F_TSO
	if (skb_shinfo(skb)->gso_size)
		return SKB_GSO_TCPV4;
#else
#ifdef  NETIF_F_UFO
        else if (skb_shinfo(skb)->ufo_size)
                return SKB_GSO_UDP;
#endif
#endif
#endif
	return 0;
}
#define	VXGE_SIZE_4K	(4 * 1024)
#define	VXGE_SIZE_8K	(8 * 1024)

static inline int VXGE_CAN_CONT_ISR(void *dev_id,
					enum __vxge_hw_channel_type type)
{
	int ret = 0;
	volatile unsigned long *napi_cnt = NULL;
	if (type == VXGE_HW_CHANNEL_TYPE_RING)
		napi_cnt = &((struct vxge_ring *)dev_id)->rx_napi_cnt;
	else
		napi_cnt = &((struct vxge_fifo *)dev_id)->tx_napi_cnt;

	if (napi_cnt)
		ret = test_and_set_bit(0, napi_cnt);
	return ret;
}

static inline void VXGE_POLL_ISR_DONE(void *dev_id, enum __vxge_hw_channel_type type)
{
	volatile unsigned long *napi_cnt;
	if (type == VXGE_HW_CHANNEL_TYPE_RING)
		napi_cnt = &((struct vxge_ring *)dev_id)->rx_napi_cnt;
	else
		napi_cnt = &((struct vxge_fifo *)dev_id)->tx_napi_cnt;

	clear_bit(0, napi_cnt);
	return;
}

static inline int is_vxge_card_up(struct vxgedev *vdev)
{
	return test_bit(__VXGE_STATE_CARD_UP, &vdev->state);
}

void vxge_config_gso(struct vxgedev *vdev, struct net_device *dev);
void vxge_config_ci_for_tti_rti(struct vxgedev *vdev);
#endif
