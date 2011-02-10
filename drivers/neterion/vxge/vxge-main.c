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
* vxge-main.c: Driver for Neterion Inc's X3100 Series 10GbE PCIe I/O
*              Virtualized Server Adapter.
* Copyright(c) 2002-2010 Exar Corp.
**********************************************************************
*
* The module loadable parameters that are supported by the driver and a brief
* explanation of all the variables:
* intr_type:
*	This configures the type of interrupt.
*		0 - INTA
*		1 - Reserved
*		2 - MSIX
* vlan_tag_strip:
*	Strip VLAN Tag enable/disable. Instructs the device to remove
*	the VLAN tag from all received tagged frames that are not
*	replicated at the internal L2 switch.
*		0 - Do not strip the VLAN tag.
*		1 - Strip the VLAN tag.
*
* promisc_en:
*	Enable promisous mode for privileged function
*		0 - DISABLE
*		1 - ENABLE
*
* promisc_all_en:
*	Enable promisous mode for all functions
*		0 - DISABLE
*		1 - ENABLE
*
* max_config_vpath:
*	This configures the maximum no of VPATH configures for each
* 	device function.
*		MIN - 1 and MAX - 17
*
* max_config_dev:
*	This configures maximum no of Device function to be enabled.
*		MIN - 1 and MAX - 17
*
* napi:
*	Enable NAPI support.
*		0 - DISABLE
*		1 - ENABLE
*
* lro:
*	Enable Large Receive Offload (LRO) / GRO
*		0 - VXGE_HW_LRO_DONOT_AGGREGATE
*		1 - VXGE_HW_LRO_ALWAYS_AGGREGATE
*		2 - VXGE_HW_LRO_DONT_AGGR_FWD_PKTS
*		3 - VXGE_HW_GRO_ENABLE
*
* rx_steering_type:
*	This parameter is for configuring the receive side steering.
*		0 - No steering
*		1 - Reserved
*		2 - RTH_TCP_UDP steering (default)
*		3 - RTH_IPV4 steering
*		4 - RTH_IPV6_EX steering
*
* tx_steering_type:
*	This parameter is for configuring the transmit steering.
*		0 - No steering
*		1 - Priority steering
*		2 - Vlan steering
*		3 - Port steering (default)
*		4 - Multiqueue steering
*
* tx_pause_enable:
*	This parameter enables pause frame generation.
*		0 - Disable
*		1 - Enable
*
* rx_pause_enable:
*	This parameter enables response to received pause frames
*		0 - Disable
*		1 - Enable
* exec_mode:
*	This is set make enable the debug mode by default.
*		0 - DISABLE
*		1 - ENABLE
*
* intr_adapt:
*	This parameter enables adaptive interrupt coalescing.
*		0 - Disable
*		1 - Enable (default)
* tx_bw:
* 	Desired max transmit bandwidth,in Mbps
*	Minimum value is 10 Mbps, for 1 Gbps specify a value of 1024.
*	This option is not supported with fw 1.8.0 onwards
*
* rx_bw:
* 	Desired max receive bandwidth,in Mbps
*	Minimum value is 100 Mbps, for 1 Gbps specify a value of 1024.
*	This option is not supported with fw 1.8.0 onwards
*
* bw:
* 	Desired max tx/rx bandwidth,in Mbps
* 	Applies the same value to tx and rx. Overrides the value present in
*	tx_bw and rx_bw
*	Minimum value is 100 Mbps for rx and 10 Mbps for tx.
*	For 1 Gbps specify a value of 1024.
*
* priority:
* 	Desired priority level for a vpath
*	Minimum value is 0 (highest priority), max value is 3 (lowest priority)
*
* func_mode:
*	Change PCI function mode.
*	0  - SF1_VP17 (1 function with 17 VPATHs)
*	1  - MF8_VP2  (8 functions with 2 VPATHs per function)
*	2  - SR17_VP1 (17 VFs with 1 VPATH per VF)
*	3  - MR17_VP1 (17 Virtual Hierarchies, 1 Path/Function/Hierarchy)
*	4  - MR8_VP2  (8 Virtual Hierarchies, 2 Path/Function/Hierarchy)
*	5  - Reserved
*	6  - SR8_VP2  (1PF, 7VF, 2 Paths/Function)
*	7  - SR4_VP4  (1PF, 3VF, 4 Paths/Function)
*	8  - MF2_VP8  (2 functions, 8 Paths/Function)
*	9  - MF4_VP4  (4 Functions, 4 Paths/Function)
*	10 - MR4_VP4  (4 Virtual Hierarchies, 4 Path/Function/Hierarchy)
*	11 - MF8P_VP2 (8 functions with 2 VPATHS per function required for
*			DirectIO in ESX)
*
* fw_upgrade:
* 	Firmware upgrade option. This driver is certified with firmware
*	version 1.8.0.
*	1 - Upgrade firmware for all adapters with firmware between 1.4.4 and 1.5.255.
*	2 - Upgrade firmware for all adapters with PXE. Force firmware upgrade for all
*	adapters with certified fw version even if adapter's current is the same.
*	3 - Upgrade firmware for all adapters without PXE. Force firmware
*	upgrade to above mentioned certified version of the firmware.
*
* factory_default:
* 	Restore factory defaults.
*	1 - Restore default.
*
* port_mode:
*	Change the default dual port mode
*	0 - Default
*	1 - Reserved
*	2 - Active/Passive
*	3 - Single Port (2nd Port offline for dual port adapter)
*	4 - Active/Active
*

* l2_switch:
*	Turn on/off the inter function traffic through the VEB, virtual
*	ethernet bridge or l2 switch.
*	0 = Disallow inter function traffic
*	1 = Allow inter function traffic
*
* max_mac_vpath:
* 	Number of entries in the hardware DA MAC table filter reserved per
* 	vpath.
* 	Minimum and default is 30
* 	Maximum is 512
*
* udp_stream:
*	Enable UDP segmentation offload for UDP packets which would
*	otherwise be fragmented.  Enabling this means that large UDP
*	packets will be split into multiple UDP packets. This feature can be
*	used for udp video streaming.
*	0 = Disable udp streaming (default)
*	1 = Enable udp streaming
*
* max_rx_buffer_size:
*	Change the size of the rx buffer allocation.
*       68 (minumum)
*       9600 (maximum/default)
*
* low_latency:
*	Configure the adapter with bw and priority settings such that one
*	function is configured for low latency.
*	0 = Disable (default)
*	1 = Enable
*	When enabled, in case of
*	- Single/multi function modes - PF is configured with highest priority.
*	- SRIOV modes - First VF is configured with highest priority.
*
* svlan_id:
*	This is the default vlanID or Service vlanID that will be inserted
*	to all the transmitted packet and will programmed to steering table.
*
* ack_aggr:
* 	This value will be used to enable / disable ACK aggregation
* 	in lro packets.
* 	0 - VXGE_HW_VPATH_AGGR_ACK_DISABLE (default)
* 	1 - VXGE_HW_VPATH_AGGR_ACK_ENABLE
*
#ifdef VXGE_PF_RING
* pf_ring_en:
*	This is used to enable/disable pf_ring feature in the driver.
*	0 = Disable (default)
*	1 = Enable
*
* pf_ring_debug:
*	This is used to enable/disable pf_ring related debug messages.
*	0 = Disable (default)
*	1 = Enable
*
#endif // PF_RING
******************************************************************************/
#include <linux/module.h>
#include <linux/if_vlan.h>
#include <linux/pci.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/version.h>
#include <linux/delay.h>
#include <linux/skbuff.h>

#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/ip.h>
#include <linux/vmalloc.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30))
#include <linux/net_tstamp.h>
#endif

#ifdef VXGE_PF_RING
#include "../../kernel/linux/pf_ring.h"
#endif /* PF_RING */

#include "vxge-main.h"
#include "vxge-reg.h"
#include "vxge-kcompat.h"

#if ((defined(VXGE_KERNEL_FW_UPGRADE)))
#include <linux/firmware.h>
#else
#include "vxge-firmware.h"
#include "vxge-firmware-pxe.h"
#endif

MODULE_LICENSE("Dual BSD/GPL");

#ifdef MODULE_VERSION
MODULE_VERSION(DRV_VERSION);
#endif

MODULE_DESCRIPTION("Neterion's X3100 Series 10GbE PCIe I/O"
	"Virtualized Server Adapter");

static struct pci_device_id vxge_id_table[] __devinitdata = {
	{PCI_VENDOR_ID_S2IO, PCI_DEVICE_ID_TITAN_WIN, PCI_ANY_ID,
	PCI_ANY_ID},
	{PCI_VENDOR_ID_S2IO, PCI_DEVICE_ID_TITAN_UNI, PCI_ANY_ID,
	PCI_ANY_ID},
	{0,}
};

MODULE_DEVICE_TABLE(pci, vxge_id_table);

VXGE_MODULE_PARAM_INT(intr_type, MSI_X);

VXGE_MODULE_PARAM_INT(vlan_tag_strip, VXGE_HW_VPATH_RPA_STRIP_VLAN_TAG_ENABLE);
VXGE_MODULE_PARAM_INT(promisc_en, VXGE_HW_PROM_MODE_DISABLE);
VXGE_MODULE_PARAM_INT(promisc_all_en, VXGE_HW_PROM_MODE_DISABLE);
VXGE_MODULE_PARAM_INT(rec_all_vid, VXGE_ALL_VID_DISABLE);
VXGE_MODULE_PARAM_INT(max_config_vpath, VXGE_USE_DEFAULT);
VXGE_MODULE_PARAM_INT(max_mac_vpath, VXGE_DEF_MAC_ADDR_COUNT);
VXGE_MODULE_PARAM_INT(max_config_dev, VXGE_MAX_CONFIG_DEV);
VXGE_MODULE_PARAM_INT(func_mode, VXGE_USE_DEFAULT);
VXGE_MODULE_PARAM_INT(fw_upgrade, VXGE_HW_FW_UPGRADE_ALL);
VXGE_MODULE_PARAM_INT(factory_default, VXGE_USE_DEFAULT);
VXGE_MODULE_PARAM_INT(port_mode, VXGE_USE_DEFAULT);
VXGE_MODULE_PARAM_INT(port_behavior, VXGE_USE_DEFAULT);
VXGE_MODULE_PARAM_INT(l2_switch, VXGE_USE_DEFAULT);
VXGE_MODULE_PARAM_INT(low_latency, VXGE_DISABLE_LOW_LATENCY_CONF);
VXGE_MODULE_PARAM_INT(ack_aggr, VXGE_HW_VPATH_AGGR_ACK_DISABLE);

static int svlan_id[VXGE_HW_MAX_VIRTUAL_FUNCTIONS] =
		{[0 ...(VXGE_HW_MAX_VIRTUAL_FUNCTIONS - 1)]
			= VXGE_HW_SVLAN_ID_DEFAULT };
static int bw[VXGE_HW_MAX_VIRTUAL_FUNCTIONS] =
		{[0 ...(VXGE_HW_MAX_VIRTUAL_FUNCTIONS - 1)]
			= VXGE_HW_VPATH_TX_BW_LIMIT_DEFAULT };
#if (VXGE_CERT_FW_VER < VXGE_FW_VER(1, 8, 0))
static int tx_bw[VXGE_HW_MAX_VPATH_ID_TX_BW_SUPPORT + 1] =
		{[0 ...(VXGE_HW_MAX_VPATH_ID_TX_BW_SUPPORT)]
			= VXGE_HW_VPATH_TX_BW_LIMIT_DEFAULT };
static int rx_bw[VXGE_HW_MAX_VIRTUAL_FUNCTIONS] =
		{[0 ...(VXGE_HW_MAX_VIRTUAL_FUNCTIONS - 1)]
			= VXGE_HW_VPATH_RX_BW_LIMIT_DEFAULT };
#endif
static int priority[VXGE_HW_MAX_VIRTUAL_FUNCTIONS] =
		{[0 ...(VXGE_HW_MAX_VIRTUAL_FUNCTIONS - 1)]
			= VXGE_HW_VPATH_PRIORITY_DEFAULT };

extern void flush_dcache_range(unsigned long start, unsigned long stop);

#ifdef module_param_array
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10))
module_param_array(bw, int, NULL, 0);
module_param_array(svlan_id, int, NULL, 0);
#if (VXGE_CERT_FW_VER < VXGE_FW_VER(1, 8, 0))
module_param_array(tx_bw, int, NULL, 0);
module_param_array(rx_bw, int, NULL, 0);
#endif
module_param_array(priority, int, NULL, 0);
#else
static int num_params = VXGE_HW_MAX_VIRTUAL_FUNCTIONS;
static int num_params_tx_bw = VXGE_HW_MAX_VPATH_ID_TX_BW_SUPPORT;
module_param_array(svlan_id, int, num_params, 0);
module_param_array(bw, int, num_params, 0);
#if (VXGE_CERT_FW_VER < VXGE_FW_VER(1, 8, 0))
module_param_array(tx_bw, int, num_params_tx_bw + 1, 0);
module_param_array(rx_bw, int, num_params, 0);
#endif
module_param_array(priority, int, num_params, 0);
#endif
#else
MODULE_PARM(svlan_id, "1-" __MODULE_STRING(VXGE_HW_MAX_VIRTUAL_FUNCTIONS) "i");
MODULE_PARM(bw, "1-" __MODULE_STRING(VXGE_HW_MAX_VIRTUAL_FUNCTIONS) "i");
#if (VXGE_CERT_FW_VER < VXGE_FW_VER(1, 8, 0))
MODULE_PARM(tx_bw, "1-" __MODULE_STRING(VXGE_HW_MAX_VPATH_ID_TX_BW_SUPPORT + 1) "i");
MODULE_PARM(rx_bw, "1-" __MODULE_STRING(VXGE_HW_MAX_VIRTUAL_FUNCTIONS) "i");
#endif
MODULE_PARM(priority, "1-" __MODULE_STRING(VXGE_HW_MAX_VIRTUAL_FUNCTIONS) "i");
#endif

#ifdef VXGE_NETDEV_POLL
VXGE_MODULE_PARAM_INT(napi, VXGE_ENABLE_NAPI);
#else
VXGE_MODULE_PARAM_INT(napi, VXGE_DISABLE_NAPI);
#endif
VXGE_MODULE_PARAM_INT(tx_steering_type, VXGE_USE_DEFAULT);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29))

VXGE_MODULE_PARAM_INT(lro, VXGE_HW_GRO_ENABLE);

#else

VXGE_MODULE_PARAM_INT(lro, VXGE_HW_LRO_DONT_AGGR_FWD_PKTS);

#endif
VXGE_MODULE_PARAM_INT(rx_steering_type, RTH_TCP_UDP_STEERING);

VXGE_MODULE_PARAM_INT(tx_pause_enable, VXGE_PAUSE_CTRL_ENABLE);
VXGE_MODULE_PARAM_INT(rx_pause_enable, VXGE_PAUSE_CTRL_ENABLE);
VXGE_MODULE_PARAM_INT(exec_mode, VXGE_EXEC_MODE_DISABLE);
VXGE_MODULE_PARAM_INT(intr_adapt, VXGE_ADAPTIVE_INTR_COALESCING_ON);

VXGE_MODULE_PARAM_INT(max_rx_buffer_size, VXGE_HW_MAX_MTU);

#ifdef NETIF_F_UFO
VXGE_MODULE_PARAM_INT(udp_stream, FALSE);
#endif

#ifdef VXGE_PF_RING
VXGE_MODULE_PARAM_INT(pf_ring_en, TRUE);
VXGE_MODULE_PARAM_INT(pf_ring_debug, FALSE);
#endif /* PF_RING */

static u16 vpath_selector[VXGE_HW_MAX_VIRTUAL_PATHS] =
		{0, 1, 3, 3, 7, 7, 7, 7, 15, 15, 15, 15, 15, 15, 15, 15, 31};

static u32 vxge_cert_eprom_image_version[VXGE_HW_MAX_ROM_IMAGES] ={
		VXGE_CERT_EPROM_IMAGE0_VER, VXGE_CERT_EPROM_IMAGE1_VER,
		VXGE_CERT_EPROM_IMAGE2_VER, VXGE_CERT_EPROM_IMAGE3_VER,
		VXGE_CERT_EPROM_IMAGE4_VER, VXGE_CERT_EPROM_IMAGE5_VER,
		VXGE_CERT_EPROM_IMAGE6_VER, VXGE_CERT_EPROM_IMAGE7_VER};
/* function modes strings */
static u8 *vxge_func_mode_names[] = {
	"Single Function - 1 func, 17 vpath",
	"Multi Function 8 - 8 func, 2 vpath per func",
	"SRIOV 17 - 17 VF, 1 vpath per VF",
	"WLPEX/SharedIO 17 - 17 VH, 1 vpath/func/hierarchy",
	"WLPEX/SharedIO 8 - 8 VH, 2 vpath/func/hierarchy",
	"Multi Function 17 - 17 func, 1 vpath per func",
	"SRIOV 8 - 1 PF, 7 VF, 2 vpath per VF",
	"SRIOV 4 - 1 PF, 3 VF, 4 vpath per VF",
	"Multi Function 2 - 2 func, 8 vpath per func",
	"Multi Function 4 - 4 func, 4 vpath per func",
	"WLPEX/SharedIO 4 - 17 func, 1 vpath per func (PCIe ARI)",
	"Multi Function 8 - For ESX DirectIO - 8 func, 2 vpath per func"
};

/* EPROM image type strings */
static u8 * vxge_eprom_image_type[] = {
	"gPXE",
	"Open firmware standard for PCI",
	"Hewlett Packard PA RISC",
	"EFI",
};

/* port modes strings */
static u8 *vxge_port_mode_names[] = {
	"Default",
	"Reserved",
	"Active/Passive",
	"Single Port",
	"Active/Active",
};

/* port behavior strings */
static u8 *vxge_port_behavior_names[] = {
	"No failover",
	"Failover only",
	"Failover & fail back"
};

/* With dynamic allocation of driver_config structure, in RHEL-4.8 the members
 * of driver_config structure will contain garbage values when accessed outside
 * probe(). Hence doing static allocation for driver_config structure.
 */
static struct vxge_drv_config drvr_config = {0, 0, 0};
static struct vxge_drv_config * const driver_config = &drvr_config;

/* @vplist is a vector into which the vpaths
 * assigned to a VF are returned after decoding the
 * mask.
 * @vpath_mask:Bits 47 to 63 indicate which VPATH is assigned
 */
static void vxge_get_vpaths(u64 vpath_mask, int *vplist)
{
	int i, pos, j = 0;

	for (i = VXGE_HW_VPATH_BMAP_END; i >= VXGE_HW_VPATH_BMAP_START; i--) {
		if (vxge_bVALn(vpath_mask, i, 1)) {
			pos = VXGE_HW_VPATH_BMAP_END - i;
			vplist[j] = pos;
			j++;
		}
	}
}

/* Helper routines to get the vpaths associated with a VF
 * @vdev: Pointer to the adapter structure
 * @vfid: Virtual function
 * @num_vpn: Returns the number of vpaths for that VF
 */
enum vxge_hw_status
vxge_get_vpn(struct vxgedev *vdev, int vfid,
	     int *num_vpn, u32 *vplist)
{
	u64 vpath_mask;
	enum vxge_hw_status status = VXGE_HW_OK;

	status = __vxge_hw_get_vpath_no(vdev->devh, vfid, num_vpn,
			&vpath_mask);

	if (status != VXGE_HW_OK)
		return status;

	vxge_get_vpaths(vpath_mask, vplist);

	return status;
}

/* Helper routines to get the vpaths associated with a VF
 * @vdev: Pointer to the adapter structure
 * @vfid: Virtual function
 * @vpath_mask:Array returning the bits indicating the vpaths
 */
int __vxge_get_vpaths(struct vxgedev *vdev, int vid, u32 *vplist)
{
	enum vxge_hw_status status = VXGE_HW_OK;
	int num_vpn = 0;

	status = vxge_get_vpn(vdev, vid, &num_vpn, vplist);
	if (status != VXGE_HW_OK) {
		vxge_debug_init(VXGE_ERR,
			"vxge_get_vpn failed with status:%d for VFID:%d",
			status, vid);
		return VXGE_HW_FAIL;
	}
	return num_vpn;
}

/*
 * vxge_hw_device_set_flow_ctrl - Set the flow control
 *
 */
enum vxge_hw_status
vxge_hw_device_set_flow_ctrl(struct __vxge_hw_device *hldev,
				 u32 tx_enable, u32 rx_enable)
{
	enum vxge_hw_status status = VXGE_HW_OK;
	int i, j;
	u32 num_vpn, vpaths = 0, num_devices = hldev->vdev->num_functions;
	u32 vplist[VXGE_HW_MAX_VIRTUAL_PATHS], high_prio_vf = 0;

	status = __vxge_hw_device_is_privilaged(hldev->host_type,
						hldev->func_id);
	if (status != VXGE_HW_OK)
		return status;

	if ((tx_enable < FLOW_CTRL_DISABLE)||
		(tx_enable > FLOW_CTRL_ENABLE_HIGH_PRIO_FUNC) ||
		(rx_enable < FLOW_CTRL_DISABLE) ||
		(rx_enable > FLOW_CTRL_ENABLE_HIGH_PRIO_FUNC))
			return VXGE_HW_FAIL;

	/* The firmware takes care of the port mode and respective
	 * pause settings in RXMAC_PAUSE_PROHIBIT_PORT0/1.
	 * So set the bit for both ports.
	 */
	for (i = 0; i < VXGE_HW_MAC_MAX_WIRE_PORTS; i++)
		vxge_hw_device_setpause_data(hldev, i, tx_enable, rx_enable);

	/* In case where rx/tx_enable_pause is set to 2 and we have only one
	 * function configured with highest priority, then
	 * set RXMAC_VCFG1.CONTRIB_L2_FLOW
	 */
	if ((rx_enable == FLOW_CTRL_ENABLE_HIGH_PRIO_FUNC ||
		tx_enable == FLOW_CTRL_ENABLE_HIGH_PRIO_FUNC))
	{
		for (i = 0; i < num_devices; i++) {
			num_vpn = __vxge_get_vpaths(hldev->vdev, i, vplist);
			for (j = 0; j < num_vpn; j++) {
				if (hldev->config.vp_config [vplist[j]].
				vp_prio == VXGE_HW_VPATH_PRIORITY_HIGH) {
					vpaths++;
					high_prio_vf = i;
				}
			}
		}
		num_vpn = __vxge_get_vpaths(hldev->vdev, high_prio_vf, vplist);
		if (vpaths == num_vpn) {
			for (j=0; j < num_vpn; j++)
				status = vxge_hw_vpath_contrib_l2_pause_enable(
							hldev, vplist[j]);
		}
	}

	return status;
}

/* Update priority configuration for both tx and rx */
void
vxge_update_priority(struct vxgedev *vdev)
{
	u32 vplist[VXGE_HW_MAX_VIRTUAL_PATHS];
	u32 num_vpn, j, i, num_func = vdev->num_functions, func_mode;
	struct __vxge_hw_device *hldev = (struct __vxge_hw_device *)vdev->devh;
	enum vxge_hw_status status = VXGE_HW_OK;

	if (low_latency) {
		status = vxge_hw_get_func_mode(hldev, &func_mode);
		if (status != VXGE_HW_OK)
			return;

		/* In case of
		 * - SRIOV and MRIOV modes, first VF is set with highest priority
		 * - Single/multi-function modes, PF is set with highest priority
		 */
		if (is_sriov(func_mode))
			priority[1] = VXGE_HW_VPATH_PRIORITY_HIGH;
		else if (is_mf(func_mode) || is_sf(func_mode))
			priority[0] = VXGE_HW_VPATH_PRIORITY_HIGH;
		else
			priority[1] = VXGE_HW_VPATH_PRIORITY_HIGH;
	}

	/* Set the priority */
	for (i = 0; i < num_func; i++) {
		num_vpn = __vxge_get_vpaths(vdev, i, vplist);
		for (j = 0; j < num_vpn; j++) {
			if (priority[i] != VXGE_HW_VPATH_PRIORITY_DEFAULT) {
				if ((priority[i] >= VXGE_HW_VPATH_PRIORITY_HIGH)
					&& (priority[i] <=
					VXGE_HW_VPATH_PRIORITY_LOW))
					hldev->config.vp_config[vplist[j]].
						vp_prio = priority[i];
			} else if (low_latency)
				hldev->config.vp_config[vplist[j]].vp_prio =
						VXGE_HW_VPATH_PRIORITY_LOW;

			vxge_hw_priority_set(hldev, vplist[j]);
		}
	}
}

/* GSO/TSO configuration based on function priority */
void vxge_config_gso(struct vxgedev *vdev, struct net_device *dev)
{
	struct __vxge_hw_device *hldev = (struct __vxge_hw_device *)vdev->devh;

	if (hldev->config.vp_config[hldev->first_vp_id].vp_prio
				!= VXGE_HW_VPATH_PRIORITY_DEFAULT) {
		/* Disbale TSO for Low prio functions if netif_set_gso_max_size
		 * if not defined.
 		 */
		if (!(VXGE_GSO_MAX_SIZE)) {
			if (hldev->config.vp_config[hldev->first_vp_id].vp_prio
					!= VXGE_HW_VPATH_PRIORITY_HIGH) {
#ifdef NETIF_F_TSO
				dev->features &= ~NETIF_F_TSO;
#ifdef NETIF_F_TSO6
				dev->features &= ~NETIF_F_TSO6;
#endif
#endif
			} else {
#ifdef NETIF_F_TSO
				dev->features |= NETIF_F_TSO;
#ifdef NETIF_F_TSO6
				dev->features |= NETIF_F_TSO6;
#endif
#endif
			}
		} else {
			/* If netif_set_gso_max_size is supported, reduce the
			 * TSO size to 8k for low priority functions (lesser
			 * than 0 priority).
			 */
			if (hldev->config.vp_config[hldev->first_vp_id].vp_prio
					!= VXGE_HW_VPATH_PRIORITY_HIGH)
				vxge_netif_set_gso_max_size(dev, VXGE_SIZE_8K);
			else
				vxge_netif_set_gso_max_size(dev,
						vdev->orig_gso_max_sz);
		}
	}
	return;
}

/* Update tx bw and priority for the vpaths in case fw version is >= 1.6.1*/
void
vxge_update_tx_bw(struct vxgedev *vdev)
{
	u32 vplist[VXGE_HW_MAX_VIRTUAL_PATHS];
	u32 num_vpn, j, i, tx_bw_is_set = 0, num_func = vdev->num_functions;
	struct __vxge_hw_device *hldev = (struct __vxge_hw_device *)vdev->devh;

	for (i = 0; i < num_func; i++) {
		num_vpn = __vxge_get_vpaths(vdev, i, vplist);
		for (j = 0; j < num_vpn; j++) {
			/* tx_bw_limit is supported only for vpaths 0-7 */
			if ( vplist[j] > VXGE_HW_MAX_VPATH_ID_TX_BW_SUPPORT)
				continue;

			if (bw[i] != VXGE_HW_VPATH_TX_BW_LIMIT_DEFAULT) {
				if ((bw[i] >= VXGE_HW_VPATH_TX_BW_LIMIT_MIN) &&
					(bw[i] <=
					VXGE_HW_VPATH_TX_BW_LIMIT_MAX))
					hldev->config.vp_config[vplist[j]].
					tx_bw_limit = ((vdev->titan1) ?
					VXGE_HW_VPATH_TX_BW_LIMIT_DEFAULT :
					bw[i]);
					tx_bw_is_set = 1;
			}
#if (VXGE_CERT_FW_VER < VXGE_FW_VER(1, 8, 0))
			else {
				if (tx_bw[i] !=
					VXGE_HW_VPATH_TX_BW_LIMIT_DEFAULT)
					if ((tx_bw[i] >=
						VXGE_HW_VPATH_TX_BW_LIMIT_MIN)
						&& (tx_bw[i] <=
						VXGE_HW_VPATH_TX_BW_LIMIT_MAX))
						hldev->config.vp_config
						[vplist[j]].tx_bw_limit =
						((vdev->titan1) ?
						VXGE_HW_VPATH_TX_BW_LIMIT_DEFAULT:
						tx_bw[i]);
					tx_bw_is_set = 1;
			}
#endif

			/* If bandwidth limiting is enabled on any of the
			 * VFs, then for remaining VFs set the bandwidth to
			 * max i.e 10 Gb) */
			if (tx_bw_is_set && hldev->config.
				vp_config[vplist[j]].tx_bw_limit ==
				VXGE_HW_VPATH_TX_BW_LIMIT_DEFAULT)
				hldev->config.vp_config[vplist[j]].tx_bw_limit =
						VXGE_HW_VPATH_TX_BW_LIMIT_MAX;

			if (hldev->config.vp_config[vplist[j]].tx_bw_limit !=
				VXGE_HW_VPATH_TX_BW_LIMIT_DEFAULT) {
				vxge_hw_tx_bw_set(hldev, vplist[j]);
			}
		}
	}
}

/* Update rx bandwidth and priority for the vpaths */
void
vxge_update_rx_bw(struct vxgedev *vdev)
{
	u32 vplist[VXGE_HW_MAX_VIRTUAL_PATHS];
	u32 num_vpn, j, i, rx_bw_is_set = 0, num_func = vdev->num_functions;
	struct __vxge_hw_device *hldev = (struct __vxge_hw_device *)vdev->devh;

	for (i = 0; i < num_func; i++) {
		num_vpn = __vxge_get_vpaths(vdev, i, vplist);
		for (j = 0; j < num_vpn; j++) {
			if (bw[i] != VXGE_HW_VPATH_RX_BW_LIMIT_DEFAULT) {
				if ((bw[i] >=
					VXGE_HW_VPATH_RX_BW_LIMIT_MIN) &&
					(bw[i] <=
					VXGE_HW_VPATH_RX_BW_LIMIT_MAX)) {
					hldev->config.vp_config[vplist[j]].
						rx_bw_limit =
						VXGE_SET_RX_BW(vdev->mtu, bw[i]);
					rx_bw_is_set = 1;
				}
			}
#if (VXGE_CERT_FW_VER < VXGE_FW_VER(1, 8, 0))
			else {
			if (rx_bw[i] !=
				VXGE_HW_VPATH_RX_BW_LIMIT_DEFAULT)
				if ((rx_bw[i] >=
					VXGE_HW_VPATH_RX_BW_LIMIT_MIN) &&
					(rx_bw[i] <=
					VXGE_HW_VPATH_RX_BW_LIMIT_MAX)) {
					hldev->config.vp_config[vplist[j]].
						rx_bw_limit =
						VXGE_SET_RX_BW(vdev->mtu,
						rx_bw[i]);
					rx_bw_is_set = 1;
				}
			}
#endif

			/* If bandwidth limiting is enabled on any of the
			 * VFs, then for remaining VFs set the bandwidth to
			 * max i.e 10 Gb) */
			if (rx_bw_is_set && hldev->config.
				vp_config[vplist[j]].rx_bw_limit ==
				VXGE_HW_VPATH_RX_BW_LIMIT_DEFAULT)
				hldev->config.vp_config[vplist[j]].rx_bw_limit =
						VXGE_HW_VPATH_RX_BW_LIMIT_MAX;

			if (hldev->config.vp_config[vplist[j]].rx_bw_limit !=
				VXGE_HW_VPATH_RX_BW_LIMIT_DEFAULT)
				vxge_hw_rx_bw_set(hldev, vplist[j]);
		}
	}
}

/* Get the number of configured devices */
u32 vxge_get_num_devices(struct vxgedev *vdev)
{
	return driver_config->config_dev_cnt;
}

/* Routine to get the privileged function number */
enum vxge_hw_status vxge_get_privilege_fn(struct vxgedev *vdev, u32 *fn)
{
	u32 priv_heirarchy;
	enum vxge_hw_status status = VXGE_HW_OK;

	status = __vxge_hw_get_priv_fn(vdev->devh, fn, &priv_heirarchy);
	if (status != VXGE_HW_OK)
		vxge_debug_init(VXGE_ERR,
				"__vxge_hw_get_priv_fn failed, status:%d",
				status);

	return status;
}

#ifdef VXGE_SELF_TEST
/*
 * @data0: Determines the parameters of test
 * data0 contains
 * [00:07] code == 1
 * [08:15] runtime_command == 0
 * [16:31] runtime_parameter == 0
 * [32:47] test_num_start == 0
 * [48:63] test_num_end == 0x30
 *
 * @data1: Defines addl parameter of the test
 * [00:15] Error action == 1 (Halt on error)
 * [16:31] Debug Level (reserved) == 0
 * [32:63] Loop == 1 (0 reserved to mean loop forever,
                other indicates the number of loops)
#define VXGE_HW_EEPROM_TEST			1
#define VXGE_HW_MDIO_PORT0_TEST			2
#define VXGE_HW_MDIO_PORT1_TEST			3
#define VXGE_HW_FLASH_TEST			0x10
#define VXGE_HW_FRAMEBUF_TEST			0x11
#define VXGE_HW_CONTEXT_MEM_TEST		0x12
*/
static void vxge_prepare_test_params(struct vxgedev *vdev,
	enum vxge_self_test test, u64 *data0, u64 *data1)
{
	u64 testnum, testparam;

	testnum = 0;
	testnum |= (u64)VXGE_HW_SELF_TEST_CODE << 56; /* Code */

	testparam = 0;
	testparam |= (u64)VXGE_HW_SELF_TEST_ERROR << 48;/* Halt on error */
	testparam |= (u64)VXGE_HW_SELF_TEST_LOOP_CNT; /* Loop once */
	switch (test) {

	case VXGE_EEPROM_ACCESS_TEST:
		testnum |= (u64)VXGE_HW_EEPROM_TEST << 16; /* Test start */
		testnum |= (u64)VXGE_HW_EEPROM_TEST; /* Test end */
		break;

	case VXGE_MDIO_PORT0_TEST:
		testnum |= (u64)VXGE_HW_MDIO_PORT0_TEST << 16;
		testnum |= (u64)VXGE_HW_MDIO_PORT0_TEST;
		break;

	case VXGE_MDIO_PORT1_TEST:
		testnum |= (u64)VXGE_HW_MDIO_PORT1_TEST << 16;
		testnum |= (u64)VXGE_HW_MDIO_PORT1_TEST;
		break;

	case VXGE_FLASH_TEST:
		testnum |= (u64)VXGE_HW_FLASH_TEST << 16;
		testnum |= (u64)VXGE_HW_FLASH_TEST;
		break;

	case VXGE_FRAME_BUFFER_TEST:
		testnum |= (u64)VXGE_HW_FRAMEBUF_TEST << 16;
		testnum |= (u64)VXGE_HW_FRAMEBUF_TEST;
		break;

	case VXGE_CONTEXT_MEM_TEST:
		testnum |= (u64)VXGE_HW_CONTEXT_MEM_TEST << 16;
		testnum |= (u64)VXGE_HW_CONTEXT_MEM_TEST;
		break;

	default:
		vxge_debug_init(VXGE_ERR,
			"%s: fatal: Undefined test \n", __func__);
	}

	*data0 = testnum;
	*data1 = testparam;

}

/*
 * vxge_perform_self_test : Perform a self test on the adapter
*/
int vxge_perform_self_test(struct vxgedev *vdev, enum vxge_self_test test)
{
	struct vxge_vpath *vpath;
	u32 priv_fn = 0;
	enum vxge_hw_status status = VXGE_HW_OK;
	u64 data0, data1; /* Input parameters to the test */

	vpath = &vdev->vpaths[priv_fn];

	vxge_prepare_test_params(vdev, test,
				&data0, &data1);

	status = __vxge_hw_start_self_test(vdev->devh, data0, data1);

	/* Check for status */
	status = __vxge_hw_poll_self_test(vdev->devh, &data0, &data1);

	return status;
}
#endif

#ifdef VXGE_LOOPBACK_TEST
static int vxge_xmit(struct sk_buff *skb, struct net_device *dev);
#endif

static inline void VXGE_COMPLETE_VPATH_TX(struct vxge_fifo *fifo)
{
	struct sk_buff **skb_ptr = NULL;
	struct sk_buff **temp;
#define NR_SKB_COMPLETED 128
	struct sk_buff *completed[NR_SKB_COMPLETED];
	int more;

	do {
		more = 0;
		skb_ptr = completed;

		if (vxge_fifo_trylock(fifo)) {
			vxge_hw_vpath_poll_tx(fifo->handle, &skb_ptr,
						NR_SKB_COMPLETED, &more);
			vxge_fifo_unlock(fifo);
		}
		/* free SKBs */
		for (temp = completed; temp != skb_ptr; temp++) {
			struct sk_buff *skb = *temp;
			dev_kfree_skb_any(skb);
		}
	} while (more);
}

static inline void VXGE_COMPLETE_ALL_TX(struct vxgedev *vdev)
{
	int i;

	/* Complete all transmits */
	for (i = 0; i < vdev->no_of_vpath; i++)
		VXGE_COMPLETE_VPATH_TX(&vdev->vpaths[i].fifo);
}

static inline void VXGE_COMPLETE_ALL_RX(struct vxgedev *vdev)
{
	int i;
	struct vxge_ring *ring;

	/* Complete all receives*/
	for (i = 0; i < vdev->no_of_vpath; i++) {
		ring = &vdev->vpaths[i].ring;
		vxge_hw_vpath_poll_rx(ring->handle);
	}
}

/*
 * MultiQ manipulation helper functions
 */
static inline int vxge_netif_queue_stopped(struct vxge_fifo *fifo,
		struct sk_buff *skb)
{
	int ret = 0;
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 26))
	struct net_device *dev = fifo->ndev;
#ifdef CONFIG_NETDEVICES_MULTIQUEUE
	int vpath_no = fifo->driver_id;
	if (fifo->tx_steering_type)
		ret = vxge_netif_subqueue_stopped(dev, skb, vpath_no);
	else
#endif
	if (fifo->queue_state == VPATH_QUEUE_STOP)
		ret = netif_queue_stopped(dev);
#else
	ret = netif_tx_queue_stopped(fifo->txq);
#endif
	return ret;
}

void vxge_stop_all_tx_queue(struct vxgedev *vdev)
{
	struct net_device *dev = vdev->ndev;
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 26))
	int i;
#ifdef CONFIG_NETDEVICES_MULTIQUEUE
	if (vdev->config.tx_steering_type) {
		for (i = 0; i < vdev->no_of_vpath; i++)
			netif_stop_subqueue(dev, i);
	} else
#endif
	{
		for (i = 0; i < vdev->no_of_vpath; i++)
			vdev->vpaths[i].fifo.queue_state = VPATH_QUEUE_STOP;
		netif_stop_queue(dev);
	}
#else
	netif_tx_stop_all_queues(dev);
#endif
}

void vxge_stop_tx_queue(struct vxge_fifo *fifo)
{
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 26))
	struct net_device *dev = fifo->ndev;
#ifdef CONFIG_NETDEVICES_MULTIQUEUE
	struct vxgedev *vdev = (struct vxgedev *)netdev_priv(dev);
	if (vdev->config.tx_steering_type)
		netif_stop_subqueue(dev, fifo->driver_id);
	else
#endif
	{
		fifo->queue_state = VPATH_QUEUE_STOP;
		netif_stop_queue(dev);
	}
#else
	netif_tx_stop_queue(fifo->txq);
#endif
}

void vxge_start_all_tx_queue(struct vxgedev *vdev)
{
	struct net_device *dev = vdev->ndev;
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 26))
	int i;
#ifdef CONFIG_NETDEVICES_MULTIQUEUE
	if (vdev->config.tx_steering_type)
		for (i = 0; i < vdev->no_of_vpath; i++)
			netif_start_subqueue(dev, i);
	else
#endif
	{
		for (i = 0; i < vdev->no_of_vpath; i++)
			vdev->vpaths[i].fifo.queue_state = VPATH_QUEUE_START;
		netif_start_queue(dev);
	}
#else
	netif_tx_start_all_queues(dev);
#endif
}

static void vxge_wake_all_tx_queue(struct vxgedev *vdev)
{
	struct net_device *dev = vdev->ndev;
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 26))
	int i;
#ifdef CONFIG_NETDEVICES_MULTIQUEUE
	if (vdev->config.tx_steering_type)
		for (i = 0; i < vdev->no_of_vpath; i++)
			netif_wake_subqueue(dev, i);
	else
#endif
	{
		for (i = 0; i < vdev->no_of_vpath; i++)
			vdev->vpaths[i].fifo.queue_state = VPATH_QUEUE_START;
		netif_wake_queue(dev);
	}
#else
	netif_tx_wake_all_queues(dev);
#endif
}

void vxge_wake_tx_queue(struct vxge_fifo *fifo, struct sk_buff *skb)
{
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 26))
	struct net_device *dev = fifo->ndev;
#ifdef CONFIG_NETDEVICES_MULTIQUEUE
	int vpath_no = fifo->driver_id;
	if (fifo->tx_steering_type) {
		if ((skb == NULL) ||
			vxge_netif_subqueue_stopped(dev, skb, vpath_no))
			netif_wake_subqueue(dev, vpath_no);
	} else
#endif
	if (fifo->queue_state == VPATH_QUEUE_STOP) {
		if (netif_queue_stopped(dev)) {
			fifo->queue_state = VPATH_QUEUE_START;
			netif_wake_queue(dev);
		}
	}
#else
	if (netif_tx_queue_stopped(fifo->txq))
		netif_tx_wake_queue(fifo->txq);
#endif
}

/* Some of the firmware return strings are padded with spaces (0x20).
This function removes those trailing spaces and NULL terminates the string */
void null_terminate(char *str, int len)
{
	do {
		if (str[len] == ' ')
			str[len] = '\0';
		else
			break;
		len--;
	} while (len != 0);
}

void print_pmd_info(struct vxgedev *vdev)
{
	int j, len;
	enum vxge_hw_status status = VXGE_HW_OK;
	u32 ports = 0;
	struct vxge_hw_device_pmd_info
		pmd_port[VXGE_HW_MAC_MAX_WIRE_PORTS] = {{0}, {0}};
	u8 pmd_type[VXGE_HW_PMD_INFO_LEN], pmd_info[VXGE_MAX_PRINT_BUF_SIZE];

	status = __vxge_hw_vpath_pmd_info_get(vdev->devh,
			vdev->vpaths[0].device_id,
			&ports,
			&pmd_port[0],
			&pmd_port[1]);

	if (status != VXGE_HW_OK)
		return;
	for (j = 0; j < ports; j++)
	{
		len = 0;
		if (pmd_port[j].type ==
			VXGE_HAL_DEVICE_PMD_TYPE_UNKNOWN) {
				printk("%s: PORT%d: VND=???, "\
				"TYP=UNSUP, PN=???, SN=???\n",
				vdev->ndev->name, j + 1);
			continue;
		}

		null_terminate(pmd_port[j].vendor,
			VXGE_HW_PMD_INFO_LEN - 1);
		len += snprintf(pmd_info + len,
			VXGE_MAX_PRINT_BUF_SIZE - len,
			"%s: PORT%d - VND=%s, ",
			vdev->ndev->name, j + 1,
			pmd_port[j].vendor);
		switch (pmd_port[j].type) {
		case VXGE_HAL_DEVICE_PMD_TYPE_10G_SR:
			strcpy(pmd_type, "10G SR");
			break;
		case VXGE_HAL_DEVICE_PMD_TYPE_10G_LR:
			strcpy(pmd_type, "10G LR");
			break;
		case VXGE_HAL_DEVICE_PMD_TYPE_10G_LRM:
			strcpy(pmd_type, "10G LRM");
			break;
		case VXGE_HAL_DEVICE_PMD_TYPE_10G_DIRECT:
			strcpy(pmd_type,
				"10G DA (Direct Attached)");
			break;
		case VXGE_HAL_DEVICE_PMD_TYPE_10G_CX4:
			strcpy(pmd_type, "10G CX4");
			break;
		case VXGE_HAL_DEVICE_PMD_TYPE_10G_BASE_T:
			strcpy(pmd_type, "10G baseT");
			break;
		case VXGE_HAL_DEVICE_PMD_TYPE_10G_OTHER:
			strcpy(pmd_type, "10G Other");
			break;
		case VXGE_HAL_DEVICE_PMD_TYPE_1G_SX:
			strcpy(pmd_type, "1G SX");
			break;
		case VXGE_HAL_DEVICE_PMD_TYPE_1G_LX:
			strcpy(pmd_type, "1G LX");
			break;
		case VXGE_HAL_DEVICE_PMD_TYPE_1G_CX:
			strcpy(pmd_type, "1G CX");
			break;
		case VXGE_HAL_DEVICE_PMD_TYPE_1G_DIRECT:
			strcpy(pmd_type,
				"1G DA (Direct Attached)");
			break;
		case VXGE_HAL_DEVICE_PMD_TYPE_1G_CX4:
			strcpy(pmd_type, "1G CX4");
			break;
		case VXGE_HAL_DEVICE_PMD_TYPE_1G_BASE_T:
			strcpy(pmd_type, "1G baseT");
			break;
		case VXGE_HAL_DEVICE_PMD_TYPE_1G_OTHER:
			strcpy(pmd_type, "1G Other");
			break;
		default:
			break;
		}
		len += snprintf(pmd_info + len,
				VXGE_MAX_PRINT_BUF_SIZE - len,
				"TYP=%s, ", pmd_type);
		null_terminate(pmd_port[j].part_num,
			VXGE_HW_PMD_INFO_LEN - 1);
		len += snprintf(pmd_info + len,
			VXGE_MAX_PRINT_BUF_SIZE - len,
			"PN=%s, ", pmd_port[j].part_num);
		null_terminate(pmd_port[j].ser_num,
			VXGE_HW_PMD_INFO_LEN - 1);
		len += snprintf(pmd_info + len,
			VXGE_MAX_PRINT_BUF_SIZE - len,
			"SN=%s\n", pmd_port[j].ser_num);
		printk("%s", pmd_info);
	}
}

/*
 * vxge_callback_link_up
 *
 * This function is called during interrupt context to notify link up state
 * change.
 */
void
vxge_callback_link_up(struct __vxge_hw_device *hldev)
{
	struct net_device *dev = hldev->ndev;
	struct vxgedev *vdev = (struct vxgedev *)netdev_priv(dev);
	struct vxge_ring *ring;
	struct __vxge_hw_ring *hw_ring;
	struct vxge_fifo *fifo;
	struct __vxge_hw_fifo *hw_fifo;
	int i;

	vxge_debug_entryexit(VXGE_TRACE, "%s: %s:%d",
		vdev->ndev->name, __func__, __LINE__);

	if (vdev->config.intr_type == MSI_X) {
		for (i = 0; i < vdev->no_of_vpath; i++) {
			ring = &vdev->vpaths[i].ring;
			hw_ring = ring->handle;
			fifo= &vdev->vpaths[i].fifo;
			hw_fifo = fifo->handle;
			vxge_hw_vpath_tti_ci_set(hw_fifo);
			hw_ring->btimer = VXGE_RTI_BTIMER_VAL;
			vxge_hw_vpath_dynamic_rti_btimer_set(hw_ring);
		}
	}

	printk(KERN_NOTICE "%s: Link Up\n", vdev->ndev->name);
	vdev->stats.link_up++;

	netif_carrier_on(vdev->ndev);
	vxge_wake_all_tx_queue(vdev);

	vxge_debug_entryexit(VXGE_TRACE,
		"%s: %s:%d Exiting...", vdev->ndev->name, __func__, __LINE__);
}

void vxge_rem_all_mac_addr(struct vxgedev *vdev)
{
	int vpath_idx;
	struct vxge_vpath *vpath;
	enum vxge_hw_status status = VXGE_HW_OK;
	struct macInfo mac_info;
	struct list_head *entry, *next;
	u8 *mac_address = NULL;
	unsigned long flags = 0;

	spin_lock_irqsave(&vdev->addr_learn_lock, flags);

	for (vpath_idx = 0; vpath_idx < vdev->no_of_vpath; vpath_idx++) {
		vpath = &vdev->vpaths[vpath_idx];
		list_for_each_safe(entry, next, &vpath->mac_addr_list) {

			if (((struct vxge_mac_addrs *)entry)->origin ==
			    VXGE_HW_VPATH_MAC_ADDR_ORIGIN_LEARNED) {
				memset(&mac_info, 0, sizeof(struct macInfo));
				mac_address = (u8 *)
				&((struct vxge_mac_addrs *)entry)->macaddr;
				memcpy(mac_info.macaddr, mac_address, ETH_ALEN);
				mac_info.vpath_no = vpath_idx;
				status = vxge_del_mac_addr(vdev, &mac_info);
			}
		}
	}

	spin_unlock_irqrestore(&vdev->addr_learn_lock, flags);
}

/*
 * vxge_callback_link_down
 *
 * This function is called during interrupt context to notify link down state
 * change.
 */
void
vxge_callback_link_down(struct __vxge_hw_device *hldev)
{
	struct net_device *dev = hldev->ndev;
	struct vxgedev *vdev = (struct vxgedev *)netdev_priv(dev);
	struct vxge_ring *ring;
	struct __vxge_hw_ring *hw_ring;
	struct vxge_fifo *fifo;
	struct __vxge_hw_fifo *hw_fifo;
	int i;

	vxge_debug_entryexit(VXGE_TRACE,
		"%s: %s:%d", vdev->ndev->name, __func__, __LINE__);

	if (vdev->config.intr_type == MSI_X) {
		for (i = 0; i < vdev->no_of_vpath; i++) {
			ring = &vdev->vpaths[i].ring;
			hw_ring = ring->handle;
			fifo = &vdev->vpaths[i].fifo;
			hw_fifo = fifo->handle;
			vxge_hw_vpath_tti_ci_reset(hw_fifo);
			hw_ring->btimer = VXGE_RTI_BTIMER_WATCHDOG_VAL;
			vxge_hw_vpath_dynamic_rti_btimer_set(hw_ring);
		}
	}

	printk(KERN_NOTICE "%s: Link Down\n", vdev->ndev->name);

	vdev->stats.link_down++;
	netif_carrier_off(vdev->ndev);
	vxge_stop_all_tx_queue(vdev);
	vxge_rem_all_mac_addr(vdev);

	vxge_debug_entryexit(VXGE_TRACE,
		"%s: %s:%d Exiting...", vdev->ndev->name, __func__, __LINE__);
}

/*
 * vxge_rx_alloc
 *
 * Allocate SKB.
 */
static struct sk_buff*
vxge_rx_alloc(void *dtrh, struct vxge_ring *ring, const int skb_size)
{
	struct net_device    *dev;
	struct sk_buff       *skb;
	struct vxge_rx_priv *rx_priv;

	dev = ring->ndev;
	vxge_debug_entryexit(VXGE_TRACE, "%s: %s:%d",
		ring->ndev->name, __func__, __LINE__);

	rx_priv = vxge_hw_ring_rxd_private_get(dtrh);

	/* try to allocate skb first. this one may fail */
	skb = netdev_alloc_skb(dev, skb_size +
	VXGE_HW_HEADER_ETHERNET_II_802_3_ALIGN);
	if (skb == NULL) {
		vxge_debug_mem(VXGE_ERR,
			"%s: out of memory to allocate SKB", dev->name);
		ring->stats.skb_alloc_fail++;
		return NULL;
	}

	vxge_debug_mem(VXGE_TRACE,
		"%s: %s:%d  Skb : 0x%p", ring->ndev->name,
		__func__, __LINE__, skb);

	skb_reserve(skb, VXGE_HW_HEADER_ETHERNET_II_802_3_ALIGN);

	rx_priv->skb = skb;
	rx_priv->skb_data = NULL;
	rx_priv->data_size = skb_size;
	vxge_debug_entryexit(VXGE_TRACE,
		"%s: %s:%d Exiting...", ring->ndev->name, __func__, __LINE__);

	return skb;
}

/*
 * vxge_rx_map
 */
static int vxge_rx_map(void *dtrh, struct vxge_ring *ring)
{
	struct vxge_rx_priv *rx_priv;
	dma_addr_t dma_addr;

	vxge_debug_entryexit(VXGE_TRACE, "%s: %s:%d",
		ring->ndev->name, __func__, __LINE__);
	rx_priv = vxge_hw_ring_rxd_private_get(dtrh);

	dma_addr =

		pci_map_single(ring->pdev, rx_priv->skb->data,
				rx_priv->data_size, PCI_DMA_FROMDEVICE);

	rx_priv->skb_data = rx_priv->skb->data;

	if (dma_addr == 0) {
		ring->stats.pci_map_fail++;
		return -EIO;
	}
	vxge_debug_mem(VXGE_TRACE,
		"%s: %s:%d  1 buffer mode dma_addr = 0x%llx",
		ring->ndev->name, __func__, __LINE__,
		(unsigned long long)dma_addr);
	vxge_hw_ring_rxd_1b_set(dtrh, dma_addr, rx_priv->data_size);

	rx_priv->data_dma = dma_addr;
	vxge_debug_entryexit(VXGE_TRACE,
		"%s: %s:%d Exiting...", ring->ndev->name, __func__, __LINE__);

	return 0;
}

/*
 * vxge_rx_initial_replenish
 * Allocation of RxD as an initial replenish procedure.
 */
static enum vxge_hw_status
vxge_rx_initial_replenish(void *dtrh, void *userdata)
{
	struct vxge_ring *ring = (struct vxge_ring *)userdata;
	struct vxgedev *vdev =  (struct vxgedev *)netdev_priv(ring->ndev);
	struct vxge_rx_priv *rx_priv;

	vxge_debug_entryexit(VXGE_TRACE, "%s: %s:%d",
		ring->ndev->name, __func__, __LINE__);

	if (vxge_rx_alloc(dtrh, ring,
		VXGE_LL_MAX_FRAME_SIZE(vdev->max_rx_buffer_size)) == NULL)
		return VXGE_HW_FAIL;

	if (vxge_rx_map(dtrh, ring)) {
		rx_priv = vxge_hw_ring_rxd_private_get(dtrh);
		dev_kfree_skb(rx_priv->skb);

		return VXGE_HW_FAIL;
	}
	vxge_debug_entryexit(VXGE_TRACE,
		"%s: %s:%d Exiting...", ring->ndev->name, __func__, __LINE__);

	return VXGE_HW_OK;
}

static inline void
vxge_rx_complete(struct vxge_ring *ring, struct sk_buff *skb, u16 vlan,
		 int pkt_length, struct vxge_hw_ring_rxd_info *ext_info)
{
	struct __vxge_hw_ring *ring_hw;
#ifdef VXGE_LOOPBACK_TEST
	u8 *mac_address = NULL;
	u64 mac_addr = 0;
#endif
#ifdef VXGE_PF_RING
	struct pfring_hooks *hook =
				(struct pfring_hooks *) ring->ndev->pfring_ptr;
#endif /* PF_RING */

	vxge_debug_entryexit(VXGE_TRACE, "%s: %s:%d",
			ring->ndev->name, __func__, __LINE__);
	ring_hw = ring->handle;

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 29))
	skb_record_rx_queue(skb, ring->driver_id);
#endif
	skb->protocol = eth_type_trans(skb, ring->ndev);

	ring->stats.rx_frms++;
	ring->stats.rx_bytes += pkt_length;

	if (skb->pkt_type == PACKET_MULTICAST)
		ring->stats.rx_mcast++;

	vxge_debug_rx(VXGE_TRACE,
		"%s: %s:%d  skb protocol = %d",
		ring->ndev->name, __func__, __LINE__, skb->protocol);

#ifdef VXGE_PF_RING
	if (pf_ring_en && hook && (hook->magic == PF_RING)) {
		/* PF_RING is enabled in the driver and is active */
		if (pf_ring_debug)
			printk(KERN_INFO "%s: [PF_RING] is alive on [%s]. "
				"Buffer length is = %d\n",
				VXGE_DRIVER_NAME, ring->ndev->name, skb->len);

		if (*hook->transparent_mode != standard_linux_path) {
			int rc = hook->ring_handler(skb, 1, 1, -1, 1);

			/* rc will be equal to 1 when the packet is
			 * handled by PF_RING and transparent_mode is
			 * set to driver2pf_ring_non_transparent
			 */
			if (rc == 1) {
				if (*hook->transparent_mode ==
					driver2pf_ring_non_transparent) {
					/* PF_RING has already freed
					 * the memory.
					 */
					return;
				}
			}
		} else {
			/* PF_RING mode is set to standard_linux_path */
			if (pf_ring_debug) {
				printk(KERN_INFO "%s: [PF_RING] is not"
					" present on %s\n",
					VXGE_DRIVER_NAME, ring->ndev->name);
				printk(KERN_INFO "%s: [PF_RING] mode for %s"
					"is set to standard_linux_path.",
					VXGE_DRIVER_NAME, ring->ndev->name);
			}
		}
	}
#endif /* PF_RING */

#ifdef VXGE_LOOPBACK_TEST
	if (skb->protocol != ntohs(ETH_P_ARP)) {
		/* Store the vpath id in the skb
		 * control buffer, this is used in the
		 * transmit to get the vpath to
		 * route the packet from */
		snprintf(skb->cb, sizeof(int), "%d", ring->driver_id);

		/* point data back to mac header */
		skb_push(skb, ETH_HLEN);

		mac_address = (u8 *)&mac_addr;
		/* swap the source and destination mac
		 * addresses
		 */
		memcpy(mac_address, &skb->data[ETH_ALEN], ETH_ALEN);
		memcpy(&skb->data[ETH_ALEN], &skb->data[0], ETH_ALEN);
		memcpy(&skb->data[0], mac_address, ETH_ALEN);

		vxge_xmit(skb, ring->ndev);
		return;
	} else {
		/* It is an ARP packet, send it to
		 * the Linux stack */
		memset(skb->cb, 0, sizeof(skb->cb));

		if (ring->napi_enable)
			netif_receive_skb(skb);
		else
			netif_rx(skb);
	}
#else
	/* Note : ext_info pointer is valid only when GRO is enabled */
	if (ring->lro_enable == VXGE_HW_GRO_ENABLE) {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29))
		/* If received vlan id matches with svlan id,
		 * do not indicate up to the stack
		 */
		if (ring->rx_vlan_stripped && ext_info->vlan &&
		(!is_svlanid_match(ring_hw, ext_info->vlan, ring->promisc_en)))
			if (ext_info->fast_path_eligible)
				vlan_gro_receive(ring->napi_p, ring->vlgrp,
					ext_info->vlan, skb);
			else
				vlan_hwaccel_receive_skb(skb,
					ring->vlgrp, ext_info->vlan);
		else
			if (ext_info->fast_path_eligible)
				napi_gro_receive(ring->napi_p, skb);
			else
				netif_receive_skb(skb);
#endif
	} else {
		/* If received vlan id matches with svlan id,
		 * do not indicate up to the stack
		 */
		if (ring->rx_vlan_stripped && vlan &&
			(!is_svlanid_match(ring_hw, vlan, ring->promisc_en))) {
			if (ring->napi_enable)
				vlan_hwaccel_receive_skb(skb,
					ring->vlgrp, vlan);
			else
				vlan_hwaccel_rx(skb, ring->vlgrp, vlan);
		} else {
			if (ring->napi_enable)
				netif_receive_skb(skb);
			else
				netif_rx(skb);
		}
	}
#endif
	vxge_debug_entryexit(VXGE_TRACE,
		"%s: %s:%d Exiting...", ring->ndev->name, __func__, __LINE__);
}

static inline void vxge_re_pre_post(void *dtr, struct vxge_ring *ring,
				    struct vxge_rx_priv *rx_priv)
{
	pci_dma_sync_single_for_device(ring->pdev,
		rx_priv->data_dma, rx_priv->data_size, PCI_DMA_FROMDEVICE);

	vxge_hw_ring_rxd_1b_set(dtr, rx_priv->data_dma, rx_priv->data_size);
	vxge_hw_ring_rxd_pre_post(ring->handle, dtr);
}

static inline void
vxge_lro_flush_sessions(struct vxge_hw_sw_lro *lro,
			struct vxge_ring *ring)
{
	while (NULL != (lro = (struct vxge_hw_sw_lro *)
		vxge_hw_sw_lro_next_session_get(ring->handle, lro))) {
		vxge_hw_update_L3L4_header(ring->handle, lro);
		vxge_rx_complete(ring, lro->os_buf, lro->vlan_tag,
					lro->os_buf->len, NULL);
		vxge_hw_sw_lro_session_close(ring->handle, lro);
		lro = NULL;
	}
}

static inline void vxge_post(void *post_dtr, struct __vxge_hw_ring *ringh)
{
	/* There is no need to avoid race condition in the RxD
	 *  replenishment process when the doorbell mode is employed.
	 * This is because the doorbell write is made after the host
	 * ownership bit of an RxD is set, and there will be at
	 * least 2 usec interval before the read from the adapter to
	 * fetch this RxD arrives.
	 * The noticeable improvement in throughput at smaller MTU sizes
	 * can likely be attributed to this modification.
	 */
	vxge_hw_ring_rxd_post_post(ringh, post_dtr);

	/* Instead of sending the doorbell write at the end of the
	 * RxD replenishment process, we need to do this as soon as
	 * rxds_limit is reached. Therefore, we need to evaluate
	 * rxds_limit condition after each RxD is replenished.
	 * The noticeable improvement in throughput at larger MTU sizes
	 * can likely be attributed to this step.
	 */
	vxge_hw_vpath_doorbell_rx(ringh, post_dtr);
}

static enum vxge_hw_status vxge_search_mac_addr_in_list(
	struct vxge_vpath *vpath, u64 del_mac)
{
	struct list_head *entry, *next;
	list_for_each_safe(entry, next, &vpath->mac_addr_list) {
		if (((struct vxge_mac_addrs *)entry)->macaddr == del_mac) {
			((struct vxge_mac_addrs *)entry)->credits++;
			return TRUE;
		}
	}
	return FALSE;
}

/*
 * vxge_rx_1b_compl
 *
 * If the interrupt is because of a received frame or if the receive ring
 * contains fresh as yet un-processed frames, this function is called.
 */
enum vxge_hw_status
vxge_rx_1b_compl(struct __vxge_hw_ring *ringh, void *dtr,
		 u8 t_code, void *userdata)
{
	struct vxge_ring *ring = (struct vxge_ring *)userdata;
	struct net_device *dev = ring->ndev;
	unsigned int dma_sizes;
	int data_size;
	dma_addr_t data_dma;
	int pkt_length;
	struct sk_buff *skb;
	struct vxge_rx_priv *rx_priv;
	struct vxge_hw_ring_rxd_info ext_info;
	struct vxge_hw_sw_lro *lro = NULL;
	struct vxgedev *vdev =  (struct vxgedev *)netdev_priv(ring->ndev);
	u8 *mac_address = NULL;
	u64 mac_addr = 0;
	unsigned long flags = 0;

	vxge_debug_entryexit(VXGE_TRACE, "%s: %s:%d",
		ring->ndev->name, __func__, __LINE__);
	do {
		prefetch((char *)dtr + L1_CACHE_BYTES);
		rx_priv = vxge_hw_ring_rxd_private_get(dtr);
		skb = rx_priv->skb;
		data_size = rx_priv->data_size;
		data_dma = rx_priv->data_dma;
		prefetch(rx_priv->skb_data);

		vxge_debug_rx(VXGE_TRACE,
			"%s: %s:%d  skb = 0x%p",
			ring->ndev->name, __func__, __LINE__, skb);

		vxge_hw_ring_rxd_1b_get(ringh, dtr, &dma_sizes);
		pkt_length = dma_sizes;

		pkt_length -= ETH_FCS_LEN;

		vxge_debug_rx(VXGE_TRACE,
			"%s: %s:%d  Packet Length = %d",
			ring->ndev->name, __func__, __LINE__, pkt_length);

		vxge_hw_ring_rxd_1b_info_get(ringh, dtr, &ext_info);
		/* check skb validity */
		vxge_assert(skb);

		prefetch((char *)skb + L1_CACHE_BYTES);

		if (unlikely(t_code > VXGE_HW_RING_T_CODE_OK)) {

			if (vxge_hw_ring_handle_tcode(ringh, dtr, t_code) !=
				VXGE_HW_OK) {

				ring->stats.rx_errors++;
				vxge_debug_rx(VXGE_TRACE,
					"%s: %s :%d Rx T_code is %d",
					ring->ndev->name, __func__,
					__LINE__, t_code);

				vxge_re_pre_post(dtr, ring, rx_priv);
				vxge_post(dtr, ringh);
				ring->stats.rx_dropped++;
				continue;
			}
		}

		/* Don't age the received mac addresses.. mainly udp packets */
		if (vdev->config.addr_learn_en) {
			if (spin_trylock_irqsave(&vdev->addr_learn_lock, flags)) {
				mac_address = (u8 *)&mac_addr;
				memcpy(mac_address, skb->data, ETH_ALEN);

				/* This increments the credits which will
				 * prevent this mac address from aging */
				vxge_search_mac_addr_in_list(
						&vdev->vpaths[ring->driver_id],
						mac_addr);
				spin_unlock_irqrestore(&vdev->addr_learn_lock, flags);
			}
		}

		if (pkt_length > VXGE_LL_RX_COPY_THRESHOLD) {

			if (vxge_rx_alloc(dtr, ring,
				VXGE_LL_MAX_FRAME_SIZE(vdev->max_rx_buffer_size)) != NULL) {

				if (!vxge_rx_map(dtr, ring)) {
					skb_put(skb, pkt_length);

					vxge_dma_unmap(ring->pdev, data_dma,
						data_size, PCI_DMA_FROMDEVICE);

					vxge_hw_ring_rxd_pre_post(ringh, dtr);
					vxge_post(dtr, ringh);
				} else {
					dev_kfree_skb(rx_priv->skb);
					rx_priv->skb = skb;
					rx_priv->data_size = data_size;
					vxge_re_pre_post(dtr, ring, rx_priv);
					vxge_post(dtr, ringh);
					ring->stats.rx_dropped++;
					break;
				}
			} else {
				vxge_re_pre_post(dtr, ring, rx_priv);
				vxge_post(dtr, ringh);
				ring->stats.rx_dropped++;
				break;
			}
		} else

			{
			struct sk_buff *skb_up;

			skb_up = netdev_alloc_skb(dev, pkt_length +
				VXGE_HW_HEADER_ETHERNET_II_802_3_ALIGN);
			if (skb_up != NULL) {
				skb_reserve(skb_up,
				    VXGE_HW_HEADER_ETHERNET_II_802_3_ALIGN);

				pci_dma_sync_single_for_cpu(ring->pdev,
					data_dma, data_size,
					PCI_DMA_FROMDEVICE);

				vxge_debug_mem(VXGE_TRACE,
					"%s: %s:%d  skb_up = %p",
					ring->ndev->name, __func__,
					__LINE__, skb);
				memcpy(skb_up->data, skb->data, pkt_length);

				vxge_re_pre_post(dtr, ring, rx_priv);
				vxge_post(dtr, ringh);
				/* will netif_rx small SKB instead */
				skb = skb_up;
				skb_put(skb, pkt_length);
			} else {
				vxge_re_pre_post(dtr, ring, rx_priv);
				vxge_post(dtr, ringh);

				vxge_debug_rx(VXGE_ERR,
					"%s: vxge_rx_1b_compl: out of "
					"memory", dev->name);
				ring->stats.skb_alloc_fail++;
				break;
			}
		}

		if ((vdev->rx_csum) && (ext_info.fast_path_eligible)) {
			skb->ip_summed = CHECKSUM_UNNECESSARY;

			if ((ring->lro_enable) &&
				(ring->lro_enable != VXGE_HW_GRO_ENABLE)) {
				u32 tcpp_len;
				enum vxge_hw_status ret;
				ext_info.dev = ring->ndev;
				ext_info.vlgrp = ring->vlgrp;
				ret = vxge_hw_sw_lro_rx_process(ringh,
					&ext_info, skb->data,
					&tcpp_len, &lro);

				if (VXGE_HW_INF_SW_LRO_CONT == ret) {
					struct sk_buff *first, *tmp;
					first = lro->os_buf;
					lro->os_buf->len += tcpp_len;
					lro->os_buf->data_len = lro->frags_len;
					if ((ring->aggr_ack) &&
						(tcpp_len == 0)) {
						dev_kfree_skb_any(skb);
						continue;
					}
					skb_pull(skb, (skb->len - tcpp_len));

					if (skb_shinfo(first)->frag_list) {
						tmp =
						  skb_shinfo(first)->frag_list;
						while (tmp->next)
							tmp = tmp->next;
						tmp->next = skb;
					} else
						skb_shinfo(first)->frag_list
									= skb;

					lro->os_buf->truesize += skb->truesize;

					continue;
				} else if (VXGE_HW_INF_SW_LRO_BEGIN == ret) {
					lro->os_buf = skb;
					continue;
				} else if (VXGE_HW_INF_SW_LRO_FLUSH_SESSION
								== ret) {
					struct sk_buff *first, *tmp;
					lro->os_buf->len += tcpp_len;
					lro->os_buf->data_len = lro->frags_len;
					if ((ring->aggr_ack) &&
						(tcpp_len == 0)) {
						dev_kfree_skb_any(skb);
						continue;
					}
					skb_pull(skb, (skb->len - tcpp_len));
					first = lro->os_buf;
					if (skb_shinfo(first)->frag_list) {
						tmp =
						  skb_shinfo(first)->frag_list;
						while (tmp->next)
							tmp = tmp->next;
						tmp->next = skb;
					} else
						skb_shinfo(first)->frag_list
									= skb;

					lro->os_buf->truesize += skb->truesize;

					vxge_rx_complete(ring, lro->os_buf,
						lro->vlan_tag,
						lro->os_buf->len,
						NULL);
					vxge_hw_sw_lro_session_close(ringh,
						lro);
					lro = NULL;
					continue;
				} else if (VXGE_HW_INF_SW_LRO_FLUSH_BOTH ==
									ret) {
					lro->os_buf->data_len = lro->frags_len;
					vxge_rx_complete(ring, lro->os_buf,
						lro->vlan_tag,
						lro->os_buf->len,
						NULL);
					vxge_hw_sw_lro_session_close(ringh,
						lro);
					lro = NULL;
				}
			}
		} else
			skb->ip_summed = CHECKSUM_NONE;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30))
		if (vdev->rx_hwts) {
			struct skb_shared_hwtstamps *skb_hwts = skb_hwtstamps(skb);
			u32 ns = *(u32 *)(skb->head + pkt_length);
			skb_hwts->hwtstamp = ns_to_ktime(ns);
			skb_hwts->syststamp.tv64 = 0;

#ifdef VXGE_PF_RING
			if(pf_ring_debug)
			  printk("[PF_RING/VXGE] hwtstamp=%llu\n", ktime_to_ns(skb_hwts->hwtstamp));
#endif
		}
#endif
#ifdef NETIF_F_RXHASH
		/* rth_hash_type and rth_it_hit are non-zero regardless of
		 * whether rss is enabled.  Only the rth_value is zero/non-zero
		 * if rss is disabled/enabled, so key off of that.
		 */
		if (ext_info.rth_value)
			skb->rxhash = ext_info.rth_value;
#endif
		vxge_rx_complete(ring, skb, ext_info.vlan,
			pkt_length, &ext_info);
		if (ring->napi_enable) {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24))
			/* NEW NAPI */
			ring->budget--;
			ring->pkts_processed++;
			if (!ring->budget)
				break;
#else
			/* OLD NAPI */
			ring->pkts_to_process -= 1;
			if (!ring->pkts_to_process)
				break;
#endif
		}
	} while (vxge_hw_ring_rxd_next_completed(ringh, &dtr,
		&t_code) == VXGE_HW_OK);

	dev->last_rx = jiffies;

	if ((ring->lro_enable) && (ring->lro_enable != VXGE_HW_GRO_ENABLE)) {
		if (lro != NULL) {
			vxge_hw_update_L3L4_header(ringh, lro);
			vxge_rx_complete(ring, lro->os_buf,
					lro->vlan_tag, lro->os_buf->len,
					NULL);
			vxge_hw_sw_lro_session_close(ringh, lro);
			lro = NULL;
		}

		/* Flush all pending LRO session */
		vxge_lro_flush_sessions(lro, ring);
	}
	vxge_debug_entryexit(VXGE_TRACE,
				"%s:%d  Exiting...",
				__func__, __LINE__);
	return VXGE_HW_OK;
}

/*
 * vxge_xmit_compl
 *
 * If an interrupt was raised to indicate DMA complete of the Tx packet,
 * this function is called. It identifies the last TxD whose buffer was
 * freed and frees all skbs whose data have already DMA'ed into the NICs
 * internal memory.
 */
enum vxge_hw_status
vxge_xmit_compl(struct __vxge_hw_fifo *fifo_hw, void *dtr,
		enum vxge_hw_fifo_tcode t_code, void *userdata,
		struct sk_buff ***skb_ptr, int nr_skb, int *more)
{
	struct vxge_fifo *fifo = (struct vxge_fifo *)userdata;
	struct sk_buff *skb, **done_skb = *skb_ptr;
	int pkt_cnt = 0;
	struct vxge_fifo_stats *stats = &fifo->stats;

	vxge_debug_entryexit(VXGE_TRACE,
		"%s:%d Entered....", __func__, __LINE__);

	do {
		int frg_cnt;
		skb_frag_t *frag;

		int i = 0, j;

		struct vxge_tx_priv *txd_priv =
			vxge_hw_fifo_txdl_private_get(dtr);

		skb = txd_priv->skb;
		frg_cnt = skb_shinfo(skb)->nr_frags;
		frag = &skb_shinfo(skb)->frags[0];

		vxge_debug_tx(VXGE_TRACE,
			"%s: %s:%d fifo_hw = %p dtr = %p "
			"tcode = 0x%x", fifo->ndev->name, __func__,
			__LINE__, fifo_hw, dtr, t_code);

		/* check skb validity */
		vxge_assert(skb);
		vxge_debug_tx(VXGE_TRACE,
			"%s: %s:%d skb = %p itxd_priv = %p frg_cnt = %d",
			fifo->ndev->name, __func__, __LINE__,
			skb, txd_priv, frg_cnt);
		if (unlikely(t_code)) {
			fifo->stats.tx_errors++;
			vxge_debug_tx(VXGE_ERR,
				"%s: tx: dtr %p completed due to "
				"error t_code %01x", fifo->ndev->name,
				dtr, t_code);
			vxge_hw_fifo_handle_tcode(fifo_hw, dtr, t_code);
		}

		/*  for unfragmented skb */
		vxge_dma_unmap(fifo->pdev, txd_priv->dma_buffers[i++],
				skb_headlen(skb), PCI_DMA_TODEVICE);

		for (j = 0; j < frg_cnt; j++) {
			pci_unmap_page(fifo->pdev,
					txd_priv->dma_buffers[i++],
					frag->size, PCI_DMA_TODEVICE);
			frag += 1;
		}

		vxge_hw_fifo_txdl_free(fifo_hw, dtr);

		/* Updating the statistics block */
		stats->tx_frms++;
		stats->tx_bytes += skb->len;

		*done_skb++ = skb;

		if (--nr_skb <= 0) {
			*more = 1;
			break;
		}

		pkt_cnt++;
		if (pkt_cnt > fifo->indicate_max_pkts)
			break;

	} while (vxge_hw_fifo_txdl_next_completed(fifo_hw,
			&dtr, &t_code) == VXGE_HW_OK);

	*skb_ptr = done_skb;
	vxge_wake_tx_queue(fifo, skb);

	vxge_debug_entryexit(VXGE_TRACE,
				"%s: %s:%d  Exiting...",
				fifo->ndev->name, __func__, __LINE__);
	return VXGE_HW_OK;
}
#ifndef VXGE_LOOPBACK_TEST

/* select a vpath to trasmit the packet */
static u32 vxge_get_vpath_no(struct vxgedev *vdev, struct sk_buff *skb,
	int *do_lock)
{
	u16 queue_len, counter = 0;
	if (skb->protocol == htons(ETH_P_IP)) {
		struct iphdr *ip;
		struct tcphdr *th;

		ip = ip_hdr(skb);

		if ((ip->frag_off & htons(IP_OFFSET|IP_MF)) == 0) {
			th = (struct tcphdr *)(((unsigned char *)ip) +
					ip->ihl*4);

			queue_len = vdev->no_of_vpath;
			counter = (ntohs(th->source) +
				ntohs(th->dest)) &
				vdev->vpath_selector[queue_len - 1];
			if (counter >= queue_len)
				counter = queue_len - 1;

#if defined(VXGE_LLTX)
			if (ip->protocol == IPPROTO_UDP)
				*do_lock = 0;
#endif /* LLTX */
		}
	}
	return counter;
}

#endif /* LOOPBACK_TEST */

int vxge_learn_mac(struct vxgedev *vdev, u8 *mac_header)
{
	struct macInfo mac_info;
	u8 *mac_address = NULL;
	u64 mac_addr = 0;
	int vpath_idx = 0;
	enum vxge_hw_status status = VXGE_HW_OK;
	struct vxge_vpath *vpath = NULL;
	struct __vxge_hw_device *hldev;
	int ret = 0;
	unsigned long flags = 0;

	hldev = (struct __vxge_hw_device *) pci_get_drvdata(vdev->pdev);

	mac_address = (u8 *)&mac_addr;
	memcpy(mac_address, mac_header, ETH_ALEN);

	if (unlikely(!spin_trylock_irqsave(&vdev->addr_learn_lock, flags)))
		return ret;

	/* Is this mac address already in the list? */
	for (vpath_idx = 0; vpath_idx < vdev->no_of_vpath; vpath_idx++) {
		vpath = &vdev->vpaths[vpath_idx];
		if (vxge_search_mac_addr_in_list(vpath, mac_addr)) {
			ret = vpath_idx;
			goto out;
		}
	}

	memset(&mac_info, 0, sizeof(struct macInfo));
	memcpy(mac_info.macaddr, mac_header, ETH_ALEN);

	/* Any vpath has room to add mac address to its da table? */
	for (vpath_idx = 0; vpath_idx < vdev->no_of_vpath; vpath_idx++) {
		vpath = &vdev->vpaths[vpath_idx];
		if (vpath->mac_addr_cnt < vpath->max_mac_addr_cnt) {
			/* Add this mac address to this vpath */
			mac_info.vpath_no = vpath_idx;
			mac_info.send_to_nw = 1;
			mac_info.origin =
				VXGE_HW_VPATH_MAC_ADDR_ORIGIN_LEARNED;
			status = vxge_add_mac_addr(vdev, &mac_info);
			if (status != VXGE_HW_OK)
				ret = -EPERM;
			else
				ret = vpath_idx;

			goto out;
		}
	}

	vpath_idx = 0;

	/* Put the function into catch basin mode */
	if (vdev->config.catch_basin_mode ==
			VXGE_CATCH_BASIN_MODE_ALWAYS_DYNAMIC) {
		if (!vdev->catch_basin_mode){
			vxge_debug_tx(VXGE_TRACE,
				      "%s: Entering catch-basin mode\n",
				      VXGE_DRIVER_NAME);
			status = vxge_hw_change_catch_basin_mode(hldev,
					VXGE_HW_CATCH_BASIN_MODE_ENABLE);
			if (status != VXGE_HW_OK) {
				vxge_debug_tx(VXGE_ERR,
					"%s: Unable to set the function"
					" %d in catch-basin mode",
					VXGE_DRIVER_NAME, hldev->func_id);
				ret = -EPERM;
				goto out;
			} else {
				vdev->catch_basin_mode = TRUE;
				vxge_debug_tx(VXGE_TRACE,
				"%s: catch basin mode set for function %d",
				VXGE_DRIVER_NAME, hldev->func_id);
			}

		}
	}

	ret = vpath_idx;
out:
	spin_unlock_irqrestore(&vdev->addr_learn_lock, flags);
	return ret;
}

void vxge_age_mac(struct vxgedev *vdev)
{
	int vpath_idx = 0;
	enum vxge_hw_status status = VXGE_HW_OK;
	struct vxge_vpath *vpath = NULL;
	struct __vxge_hw_device *hldev;
	struct list_head *entry, *next;
	struct macInfo mac_info;
	u8 *mac_address = NULL;
	unsigned long flags = 0;
	u8 disable_cb = 0;

	hldev = (struct __vxge_hw_device *) pci_get_drvdata(vdev->pdev);

	vdev->timer_cnt++;
	if (vdev->timer_cnt < VXGE_TIMER_COUNT)
		return;

	/* If the MAC address has 0 credit then delete the MAC Address,
	* otherwise reset the credit to 0.
	*/

	if (unlikely(!spin_trylock_irqsave(&vdev->addr_learn_lock, flags))) {
		vxge_debug_intr(VXGE_TRACE, "%s: %s:%d trylock failed",
			VXGE_DRIVER_NAME, __func__, __LINE__);
		return;
	}

	for (vpath_idx = 0; vpath_idx < vdev->no_of_vpath; vpath_idx++) {
		vpath = &vdev->vpaths[vpath_idx];

		list_for_each_safe(entry, next, &vpath->mac_addr_list) {
			if (((struct vxge_mac_addrs *)entry)->credits != 0) {
				((struct vxge_mac_addrs *)entry)->credits = 0;
			} else {
				if (((struct vxge_mac_addrs *)entry)->origin ==
				    VXGE_HW_VPATH_MAC_ADDR_ORIGIN_LEARNED) {

					memset(&mac_info, 0,
					       sizeof(struct macInfo));
					mac_address = (u8 *)
					&((struct vxge_mac_addrs *)entry)->macaddr;
					memcpy(mac_info.macaddr, mac_address,
					       ETH_ALEN);
					mac_info.vpath_no = vpath_idx;
					status = vxge_del_mac_addr(vdev,
								   &mac_info);
				}
			}
		}

		/* Now after aging if any vpath has room, then let's disable
		* catch basin.
		*/
		if ((vdev->catch_basin_mode) &&
		    (vpath->mac_addr_cnt < vpath->max_mac_addr_cnt)) {
			disable_cb = TRUE;
		}
	}

	if (vdev->config.catch_basin_mode ==
			VXGE_CATCH_BASIN_MODE_ALWAYS_DYNAMIC) {
		if (disable_cb) {
			/* Take the VF out of catch basin mode */
			status = vxge_hw_change_catch_basin_mode(hldev,
					 VXGE_HW_CATCH_BASIN_MODE_DISABLE);
			if (status != VXGE_HW_OK) {
				vxge_debug_tx(VXGE_ERR,
					"%s: Unable to disable catch "
					"basin for the function %d\n",
					 VXGE_DRIVER_NAME, hldev->func_id);
			}else{
				vdev->catch_basin_mode = FALSE;
				vxge_debug_tx(VXGE_TRACE,
					"%s: Catch-basin mode "
					"disabled for function id = %d\n",
					VXGE_DRIVER_NAME, hldev->func_id);
			}
		}
	}
	vdev->timer_cnt = 0;

	spin_unlock_irqrestore(&vdev->addr_learn_lock, flags);
	return;
}

/**
 * vxge_xmit
 * @skb : the socket buffer containing the Tx data.
 * @dev : device pointer.
 *
 * This function is the Tx entry point of the driver. Neterion NIC supports
 * certain protocol assist features on Tx side, namely  CSO, S/G, LSO.
 * NOTE: when device cant queue the pkt, just the trans_start variable will
 * not be upadted.
*/
static int
vxge_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct vxge_fifo *fifo = NULL;
	void *dtr_priv;
	void *dtr = NULL;
	struct vxgedev *vdev = NULL;
	enum vxge_hw_status status;
	int frg_cnt, first_frg_len;
	skb_frag_t *frag;
	int i = 0, j = 0, avail;
	struct vxge_tx_priv *txdl_priv = NULL;
	struct __vxge_hw_fifo *fifo_hw;
#if (defined(NETIF_F_TSO) || defined(NETIF_F_UFO))
	int offload_type;
#endif
#if defined(VXGE_LLTX)
	unsigned long flags = 0;
#endif /* LLTX */
#if (!defined(ESX_KL) || defined(VXGE_LLTX))
	int do_spin_tx_lock = 1;
#endif
	int vpath_no = 0;
	struct __vxge_hw_device  *hldev;

	u64 dma_pointer;

	vxge_debug_entryexit(VXGE_TRACE, "%s: %s:%d",
			dev->name, __func__, __LINE__);

	/* A buffer with no data will be dropped */
	if (unlikely(skb->len <= 0)) {
		vxge_debug_tx(VXGE_ERR,
			"%s: Buffer has no data..", dev->name);
		dev_kfree_skb(skb);
		return NETDEV_TX_OK;
	}

	vdev = (struct vxgedev *)netdev_priv(dev);
	hldev = (struct __vxge_hw_device  *)pci_get_drvdata(vdev->pdev);

	if (unlikely(!is_vxge_card_up(vdev))) {
		vxge_debug_tx(VXGE_ERR,
			"%s: vdev not initialized", dev->name);
		dev_kfree_skb(skb);
		return NETDEV_TX_OK;
	}

	/* learn the mac address for only broadcast packets */
	if (vdev->config.addr_learn_en) {
		vpath_no = vxge_learn_mac(vdev, skb->data + ETH_ALEN);
		if (vpath_no == -EPERM) {
			vxge_debug_tx(VXGE_ERR,
				"%s: Failed to store the mac address",
				dev->name);
			dev_kfree_skb(skb);
			return NETDEV_TX_OK;
		}
	}

#ifdef VXGE_LOOPBACK_TEST
	vpath_no = simple_strtol(skb->cb, NULL, 0);
#else

	if (vdev->config.tx_steering_type == TX_MULTIQ_STEERING)
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 26))
		vpath_no = skb_get_queue_mapping(skb);
#else
		vpath_no = vxge_get_vpath_no(vdev, skb, &do_spin_tx_lock);
#endif
	else if (vdev->config.tx_steering_type == TX_PORT_STEERING)
		vpath_no = vxge_get_vpath_no(vdev, skb, &do_spin_tx_lock);

	vxge_debug_tx(VXGE_TRACE, "%s: vpath_no= %d", dev->name, vpath_no);
#endif

	if (vpath_no >= vdev->no_of_vpath)
		vpath_no = 0;

	fifo = &vdev->vpaths[vpath_no].fifo;
	fifo_hw = fifo->handle;

#if defined(VXGE_LLTX)
	if (do_spin_tx_lock)
		spin_lock_irqsave(&fifo->tx_lock, flags);
	else {
		if (unlikely(!spin_trylock_irqsave(&fifo->tx_lock, flags)))
			return NETDEV_TX_LOCKED;
	}

	if (vxge_netif_queue_stopped(fifo, skb)) {
		spin_unlock_irqrestore(&fifo->tx_lock, flags);
		return NETDEV_TX_BUSY;
	}
#else
	if (netif_tx_queue_stopped(fifo->txq))
		return NETDEV_TX_BUSY;
#endif /* LLTX */

	avail = vxge_hw_fifo_free_txdl_count_get(fifo_hw);
	if (avail == 0) {
#if defined(VXGE_LLTX)
		spin_unlock_irqrestore(&fifo->tx_lock, flags);
		VXGE_COMPLETE_VPATH_TX(fifo);
		if (do_spin_tx_lock)
			spin_lock_irqsave(&fifo->tx_lock, flags);
		else {
			if (unlikely(!spin_trylock_irqsave(&fifo->tx_lock,
				flags)))
				return NETDEV_TX_LOCKED;
		}
		avail = vxge_hw_fifo_free_txdl_count_get(fifo_hw);
		if (avail == 0) {
#endif /* LLTX */
			vxge_debug_tx(VXGE_ERR,
				"%s: No free TXDs available", dev->name);
			fifo->stats.txd_not_free++;
			vxge_stop_tx_queue(fifo);
			goto _exit1;
#if defined(VXGE_LLTX)
		}
#endif /* LLTX */
	}

	/* Last TXD?  Stop tx queue to avoid dropping packets.  TX
	 * completion will resume the queue.
	 */
	if (avail == 1)
		vxge_stop_tx_queue(fifo);

	status = vxge_hw_fifo_txdl_reserve(fifo_hw, &dtr, &dtr_priv);
	if (unlikely(status != VXGE_HW_OK)) {
		vxge_debug_tx(VXGE_ERR,
		   "%s: Out of descriptors .", dev->name);
		fifo->stats.txd_out_of_desc++;
		vxge_stop_tx_queue(fifo);
		goto _exit1;
	}

	vxge_debug_tx(VXGE_TRACE,
		"%s: %s:%d fifo_hw = %p dtr = %p dtr_priv = %p",
		dev->name, __func__, __LINE__,
		fifo_hw, dtr, dtr_priv);

	/*
	 * If svlan id is valid update svlan id instead of stack
	 * provided vlan id
	 */
	if (fifo_hw->s_vid != VXGE_HW_SVLAN_ID_DEFAULT) {
		u16 vlan_tag = fifo_hw->s_vid;
		vxge_hw_fifo_txdl_vlan_set(dtr, vlan_tag);
	} else if (vdev->vlgrp && vlan_tx_tag_present(skb)) {
		u16 vlan_tag = vlan_tx_tag_get(skb);
		vxge_hw_fifo_txdl_vlan_set(dtr, vlan_tag);
	}

	first_frg_len = skb_headlen(skb);

	dma_pointer =

		pci_map_single(fifo->pdev,
			skb->data, first_frg_len, PCI_DMA_TODEVICE);

	if (unlikely(vxge_do_pci_dma_mapping_error(fifo->pdev, dma_pointer))) {
		vxge_hw_fifo_txdl_free(fifo_hw, dtr);
		vxge_stop_tx_queue(fifo);
		fifo->stats.pci_map_fail++;
		goto _exit1;
	}
	txdl_priv = vxge_hw_fifo_txdl_private_get(dtr);
	txdl_priv->skb = skb;
	txdl_priv->dma_buffers[j] = dma_pointer;

	frg_cnt = skb_shinfo(skb)->nr_frags;
	vxge_debug_tx(VXGE_TRACE,
			"%s: %s:%d skb = %p txdl_priv = %p "
			"frag_cnt = %d dma_pointer = 0x%llx", dev->name,
			__func__, __LINE__, skb, txdl_priv,
			frg_cnt, (unsigned long long)dma_pointer);

	vxge_hw_fifo_txdl_buffer_set(fifo_hw, dtr, j++, dma_pointer,
		first_frg_len);

	frag = &skb_shinfo(skb)->frags[0];
	for (i = 0; i < frg_cnt; i++) {
		/* ignore 0 length fragment */
		if (!frag->size)
			continue;

		dma_pointer =

			(u64)pci_map_page(
				fifo->pdev, frag->page,
				frag->page_offset, frag->size,
				PCI_DMA_TODEVICE);

		if (unlikely(vxge_do_pci_dma_mapping_error(fifo->pdev, dma_pointer)))
			goto _exit0;
		vxge_debug_tx(VXGE_TRACE,
			"%s: %s:%d frag = %d dma_pointer = 0x%llx",
				dev->name, __func__, __LINE__, i,
				(unsigned long long)dma_pointer);

		txdl_priv->dma_buffers[j] = dma_pointer;
		vxge_hw_fifo_txdl_buffer_set(fifo_hw, dtr, j++, dma_pointer,
					frag->size);
		frag += 1;
	}

#ifdef NETIF_F_TSO
	if (is_tso_enabled(dev)) {
		offload_type = vxge_offload_type(skb);

		if (offload_type & (SKB_GSO_TCPV6 | SKB_GSO_TCPV4)) {
			int mss = skb_is_gso(skb);

			if (mss) {
				vxge_debug_tx(VXGE_TRACE,
					"%s: %s:%d mss = %d",
					dev->name, __func__, __LINE__, mss);
				vxge_hw_fifo_txdl_mss_set(dtr, mss);
			} else {
				vxge_assert(skb->len <=
					dev->mtu + VXGE_HW_MAC_HEADER_MAX_SIZE);
				vxge_assert(0);
				goto _exit0;
			}
		}
	}
#endif
#ifdef NETIF_F_UFO
	offload_type = vxge_offload_type(skb);

	if (offload_type == SKB_GSO_UDP) {

		struct iphdr *ip;
		int mss = vxge_udp_mss(skb);

		mss &= ~7; /* MSS must be a multiple of 8 bytes */
		mss -= 8;	/* hardware doesn't want the UDP header */
		if (mss) {
			vxge_debug_tx(VXGE_TRACE,
				"%s: %s:%d mss = %d",
				dev->name, __func__, __LINE__, mss);
			vxge_hw_fifo_txdl_mss_set(dtr, mss);
			if (skb->protocol == htons(ETH_P_IP)) {
				/* hw will spilt the packet in to multiple
				 * mss sized packets, adjust the ip->id */
				ip = ip_hdr(skb);
				ip->id = ip->id * ((skb->len / mss) + 1);
			}
		} else {
			vxge_assert(skb->len <=
				dev->mtu + VXGE_HW_MAC_HEADER_MAX_SIZE);
			vxge_assert(0);
			goto _exit0;
		}
	}
#endif

	if (skb->ip_summed == CHECKSUM_PARTIAL)
		vxge_hw_fifo_txdl_cksum_set_bits(dtr,
					VXGE_HW_FIFO_TXD_TX_CKO_IPV4_EN |
					VXGE_HW_FIFO_TXD_TX_CKO_TCP_EN |
					VXGE_HW_FIFO_TXD_TX_CKO_UDP_EN);

	vxge_hw_fifo_txdl_post(fifo_hw, dtr);

#if defined(VXGE_LLTX)
	dev->trans_start = jiffies;
	spin_unlock_irqrestore(&fifo->tx_lock, flags);
#endif /* LLTX */
	vxge_debug_entryexit(VXGE_TRACE, "%s: %s:%d  Exiting...",
		dev->name, __func__, __LINE__);
	return 0;

_exit0:

	j = 0;
	frag = &skb_shinfo(skb)->frags[0];

	pci_unmap_single(fifo->pdev, txdl_priv->dma_buffers[j++],
			skb_headlen(skb), PCI_DMA_TODEVICE);

	for (; j < i; j++) {
		pci_unmap_page(fifo->pdev,
			txdl_priv->dma_buffers[j],
			frag->size,
			PCI_DMA_TODEVICE);
		frag += 1;
	}

	vxge_hw_fifo_txdl_free(fifo_hw, dtr);
_exit1:
	dev_kfree_skb(skb);
#if defined(VXGE_LLTX)
	spin_unlock_irqrestore(&fifo->tx_lock, flags);
	VXGE_COMPLETE_VPATH_TX(fifo);
#endif /* LLTX */
	return 0;
}
/*
 * vxge_rx_term
 *
 * Function will be called by hw function to abort all outstanding receive
 * descriptors.
 */
static void
vxge_rx_term(void *dtrh, enum vxge_hw_rxd_state state, void *userdata)
{

	struct vxge_ring *ring = (struct vxge_ring *)userdata;

	struct vxge_rx_priv *rx_priv =
		vxge_hw_ring_rxd_private_get(dtrh);

	vxge_debug_entryexit(VXGE_TRACE, "%s: %s:%d",
			ring->ndev->name, __func__, __LINE__);
	if (state != VXGE_HW_RXD_STATE_POSTED)
		return;

	vxge_dma_unmap(ring->pdev, rx_priv->data_dma,
		rx_priv->data_size, PCI_DMA_FROMDEVICE);

	if (rx_priv->skb)
		dev_kfree_skb(rx_priv->skb);
	rx_priv->skb_data = NULL;

	vxge_debug_entryexit(VXGE_TRACE,
		"%s: %s:%d  Exiting...",
		ring->ndev->name, __func__, __LINE__);
}

/*
 * vxge_tx_term
 *
 * Function will be called to abort all outstanding tx descriptors
 */
static void
vxge_tx_term(void *dtrh, enum vxge_hw_txdl_state state, void *userdata)
{

	struct vxge_fifo *fifo = (struct vxge_fifo *)userdata;
	skb_frag_t *frag;
	int i = 0, j, frg_cnt;

	struct vxge_tx_priv *txd_priv = vxge_hw_fifo_txdl_private_get(dtrh);
	struct sk_buff *skb = txd_priv->skb;

	vxge_debug_entryexit(VXGE_TRACE, "%s:%d", __func__, __LINE__);

	if (state != VXGE_HW_TXDL_STATE_POSTED)
		return;

	/* check skb validity */
	vxge_assert(skb);

	frg_cnt = skb_shinfo(skb)->nr_frags;
	frag = &skb_shinfo(skb)->frags[0];

	/*  for unfragmented skb */
	pci_unmap_single(fifo->pdev, txd_priv->dma_buffers[i++],
		skb_headlen(skb), PCI_DMA_TODEVICE);

	for (j = 0; j < frg_cnt; j++) {
		pci_unmap_page(fifo->pdev, txd_priv->dma_buffers[i++],
			       frag->size, PCI_DMA_TODEVICE);
		frag += 1;
	}

	dev_kfree_skb(skb);

	vxge_debug_entryexit(VXGE_TRACE,
		"%s:%d  Exiting...", __func__, __LINE__);
}

/**
 * vxge_set_multicast
 * @dev: pointer to the device structure
 *
 * Entry point for multicast address enable/disable
 * This function is a driver entry point which gets called by the kernel
 * whenever multicast addresses must be enabled/disabled. This also gets
 * called to set/reset promiscuous mode. Depending on the deivce flag, we
 * determine, if multicast address must be enabled or if promiscuous mode
 * is to be disabled etc.
 */
static void vxge_set_multicast(struct net_device *dev)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 35))
	struct netdev_hw_addr *ha;
#else
	struct dev_mc_list *mclist;
#endif
	struct vxgedev *vdev;
	int i, mcast_cnt = 0;
	struct __vxge_hw_device  *hldev;
	struct vxge_vpath *vpath;
	enum vxge_hw_status status = VXGE_HW_OK;
	struct macInfo mac_info;
	int vpath_idx = 0;
	struct vxge_mac_addrs *mac_entry;
	struct list_head *list_head;
	struct list_head *entry, *next;
	u8 *mac_address = NULL;
	unsigned long flags = 0;

	vxge_debug_entryexit(VXGE_TRACE,
		"%s:%d", __func__, __LINE__);

	vdev = (struct vxgedev *)netdev_priv(dev);
	hldev = (struct __vxge_hw_device  *)vdev->devh;

	if (unlikely(!is_vxge_card_up(vdev)))
		return;

	spin_lock_irqsave(&vdev->addr_learn_lock, flags);

	if ((dev->flags & IFF_ALLMULTI) && (!vdev->all_multi_flg)) {
		for (i = 0; i < vdev->no_of_vpath; i++) {
			vpath = &vdev->vpaths[i];
			vxge_assert(vpath->is_open);
			status = vxge_hw_vpath_mcast_enable(vpath->handle);
			vdev->all_multi_flg = 1;
		}
	} else if (!(dev->flags & IFF_ALLMULTI) && (vdev->all_multi_flg)) {
		for (i = 0; i < vdev->no_of_vpath; i++) {
			vpath = &vdev->vpaths[i];
			vxge_assert(vpath->is_open);
			status = vxge_hw_vpath_mcast_disable(vpath->handle);
			vdev->all_multi_flg = 0;
		}
	}

	if (status != VXGE_HW_OK)
		vxge_debug_init(VXGE_ERR,
			"failed to %s multicast, status %d",
			dev->flags & IFF_ALLMULTI ?
			"enable" : "disable", status);

	if ((dev->flags & IFF_PROMISC) && (!vdev->prev_promisc_flg)) {
		for (i = 0; i < vdev->no_of_vpath; i++) {
			vpath = &vdev->vpaths[i];
			vxge_assert(vpath->is_open);

			if (vdev->config.promisc_all_en) {
				vxge_hw_vpath_promisc_enable(vpath->handle);
				vdev->prev_promisc_flg = 1;
			} else if (vdev->config.promisc_en &&
				(vdev->devh->access_rights &
				VXGE_HW_DEVICE_ACCESS_RIGHT_MRPCIM)) {
				vxge_hw_vpath_promisc_enable(
					vdev->vpaths[i].handle);
				vdev->prev_promisc_flg = 1;
			} else {
				status =
				    vxge_hw_vpath_mcast_enable(vpath->handle);
				vdev->config.addr_learn_en =
					ENABLE_ADDR_LEARNING;
			}
		}
	} else if (!(dev->flags & IFF_PROMISC) && (vdev->prev_promisc_flg)) {
		for (i = 0; i < vdev->no_of_vpath; i++) {
			vpath = &vdev->vpaths[i];
			vxge_assert(vpath->is_open);

			if (vdev->config.promisc_all_en) {
				vxge_hw_vpath_promisc_disable(vpath->handle);
				vdev->prev_promisc_flg = 0;
			} else if (vdev->config.promisc_en &&
				(vdev->devh->access_rights &
				VXGE_HW_DEVICE_ACCESS_RIGHT_MRPCIM)) {
				vxge_hw_vpath_promisc_disable(vpath->handle);
				vdev->prev_promisc_flg = 0;
			}

			if (vdev->config.addr_learn_en) {
				vdev->config.addr_learn_en =
					DISABLE_ADDR_LEARNING;
				status =
				    vxge_hw_vpath_mcast_disable(vpath->handle);
			}
		}
	}

	memset(&mac_info, 0, sizeof(struct macInfo));
	/* Update individual M_CAST address list */
	if ((!vdev->all_multi_flg) && vxge_netdev_mc_count(dev)) {

		mcast_cnt = vdev->vpaths[0].mcast_addr_cnt;
		list_head = &vdev->vpaths[0].mac_addr_list;
		if ((vxge_netdev_mc_count(dev) +
			(vdev->vpaths[0].mac_addr_cnt - mcast_cnt)) >
				vdev->vpaths[0].max_mac_addr_cnt)
			goto _set_all_mcast;

		/* Delete previous MC's */
		for (i = 0; i < mcast_cnt; i++) {
			if (!list_empty(list_head))
				mac_entry = (struct vxge_mac_addrs *)
					list_entry(list_head->next,
						struct vxge_mac_addrs,
						item);

			list_for_each_safe(entry, next, list_head) {

				mac_entry = (struct vxge_mac_addrs *) entry;
				/* Copy the mac address to delete */
				mac_address = (u8 *)&mac_entry->macaddr;
				memcpy(mac_info.macaddr, mac_address, ETH_ALEN);

				/* Is this a multicast address */
				if (0x01 & mac_info.macaddr[0]) {
					for (vpath_idx = 0; vpath_idx <
						vdev->no_of_vpath;
						vpath_idx++) {
						mac_info.vpath_no = vpath_idx;
						status = vxge_del_mac_addr(
								vdev,
								&mac_info);
					}
				}
			}
		}

		/* Add new ones */
		i = 0;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 35))
		netdev_for_each_mc_addr(ha, dev) {
			memcpy(mac_info.macaddr, ha->addr, ETH_ALEN);
#else
		netdev_for_each_mc_addr(mclist, dev) {
			memcpy(mac_info.macaddr, mclist->dmi_addr, ETH_ALEN);
#endif
			for (vpath_idx = 0; vpath_idx < vdev->no_of_vpath;
					vpath_idx++) {
				mac_info.vpath_no = vpath_idx;
				mac_info.origin =
				VXGE_HW_VPATH_MAC_ADDR_ORIGIN_NOT_LEARNED;
				status = vxge_add_mac_addr(vdev, &mac_info);
				if (status != VXGE_HW_OK) {
					vxge_debug_init(VXGE_ERR,
						"%s:%d Setting individual"
						"multicast address failed",
						__func__, __LINE__);
					goto _set_all_mcast;
				}
			}
			i++;
		}

		spin_unlock_irqrestore(&vdev->addr_learn_lock, flags);
		return;
_set_all_mcast:
		mcast_cnt = vdev->vpaths[0].mcast_addr_cnt;
		/* Delete previous MC's */
		for (i = 0; i < mcast_cnt; i++) {

			list_for_each_safe(entry, next, list_head) {

				mac_entry = (struct vxge_mac_addrs *) entry;
				/* Copy the mac address to delete */
				mac_address = (u8 *)&mac_entry->macaddr;
				memcpy(mac_info.macaddr, mac_address, ETH_ALEN);

				/* Is this a multicast address */
				if (0x01 & mac_info.macaddr[0])
					break;
			}

			for (vpath_idx = 0; vpath_idx < vdev->no_of_vpath;
					vpath_idx++) {
				mac_info.vpath_no = vpath_idx;
				status = vxge_del_mac_addr(vdev, &mac_info);
			}
		}

		/* Enable all multicast */
		for (i = 0; i < vdev->no_of_vpath; i++) {
			vpath = &vdev->vpaths[i];
			vxge_assert(vpath->is_open);

			status = vxge_hw_vpath_mcast_enable(vpath->handle);
			if (status != VXGE_HW_OK) {
				vxge_debug_init(VXGE_ERR,
					"%s:%d Enabling all multicasts failed",
					 __func__, __LINE__);
			}
			vdev->all_multi_flg = 1;
		}
		dev->flags |= IFF_ALLMULTI;
	}

	spin_unlock_irqrestore(&vdev->addr_learn_lock, flags);
	vxge_debug_entryexit(VXGE_TRACE,
		"%s:%d  Exiting...", __func__, __LINE__);
}

/**
 * vxge_set_mac_addr
 * @dev: pointer to the device structure
 *
 * Update entry "0" (default MAC addr)
 */
static int vxge_set_mac_addr(struct net_device *dev, void *p)
{
	struct sockaddr *addr = p;
	struct vxgedev *vdev;
	struct __vxge_hw_device  *hldev;
	int status = VXGE_HW_OK;
	struct macInfo mac_info_new, mac_info_old;
	int vpath_idx = 0;
	unsigned long flags = 0;

	vxge_debug_entryexit(VXGE_TRACE, "%s:%d", __func__, __LINE__);

	vdev = (struct vxgedev *)netdev_priv(dev);
	hldev = vdev->devh;

	spin_lock_irqsave(&vdev->addr_learn_lock, flags);

	if (!is_valid_ether_addr(addr->sa_data)) {
		status = -EINVAL;
		goto ret;
	}

	memset(&mac_info_new, 0, sizeof(struct macInfo));
	memset(&mac_info_old, 0, sizeof(struct macInfo));

	vxge_debug_entryexit(VXGE_TRACE, "%s:%d  Exiting...",
		__func__, __LINE__);

	/* Get the old address */
	memcpy(mac_info_old.macaddr, dev->dev_addr, dev->addr_len);

	/* Copy the new address */
	memcpy(mac_info_new.macaddr, addr->sa_data, dev->addr_len);

	/* First delete the old mac address from all the vpaths
	as we can't specify the index while adding new mac address */
	for (vpath_idx = 0; vpath_idx < vdev->no_of_vpath; vpath_idx++) {
		struct vxge_vpath *vpath = &vdev->vpaths[vpath_idx];
		if (!vpath->is_open) {
			/* This can happen when this interface is added/removed
			to the bonding interface. Delete this station address
			from the linked list */
			vxge_mac_list_del(vpath, &mac_info_old);

			/* Add this new address to the linked list
			for later restoring */
			vxge_mac_list_add(vpath, &mac_info_new);

			continue;
		}
		/* Delete the station address */
		mac_info_old.vpath_no = vpath_idx;
		status = vxge_del_mac_addr(vdev, &mac_info_old);
	}

	if (unlikely(!is_vxge_card_up(vdev))) {
		memcpy(dev->dev_addr, addr->sa_data, dev->addr_len);
		status = VXGE_HW_OK;
		goto ret;
	}

	/* Set this mac address to all the vpaths */
	for (vpath_idx = 0; vpath_idx < vdev->no_of_vpath; vpath_idx++) {
		mac_info_new.vpath_no = vpath_idx;
		mac_info_new.origin = VXGE_HW_VPATH_MAC_ADDR_ORIGIN_NOT_LEARNED;
		mac_info_new.send_to_nw = 1;

		status = vxge_add_mac_addr(vdev, &mac_info_new);
		if (status != VXGE_HW_OK) {
			status = -EINVAL;
			goto ret;
		}
	}

	memcpy(dev->dev_addr, addr->sa_data, dev->addr_len);

ret:
	spin_unlock_irqrestore(&vdev->addr_learn_lock, flags);

	return status;
}

/*
 * vxge_vpath_intr_enable
 * @vdev: pointer to vdev
 * @vp_id: vpath for which to enable the interrupts
 *
 * Enables the interrupts for the vpath
*/
void vxge_vpath_intr_enable(struct vxgedev *vdev, int vp_id)
{
	struct vxge_vpath *vpath = &vdev->vpaths[vp_id];
	int msix_id = 0;
	int tim_msix_id[4] = {0, 1, 0, 0};
	int alarm_msix_id = VXGE_ALARM_MSIX_ID;

	vxge_hw_vpath_intr_enable(vpath->handle);

	if (vdev->config.intr_type == INTA)
		vxge_hw_vpath_inta_unmask_tx_rx(vpath->handle);
	else {

		vxge_hw_vpath_msix_set(vpath->handle, tim_msix_id,
			alarm_msix_id);

		msix_id = vpath->device_id * VXGE_HW_VPATH_MSIX_ACTIVE;

		vxge_hw_vpath_msix_unmask(vpath->handle, msix_id);
		vxge_hw_vpath_msix_unmask(vpath->handle, msix_id + 1);

		/* enable the alarm vector */
		msix_id = (vpath->handle->vpath->hldev->first_vp_id *
			VXGE_HW_VPATH_MSIX_ACTIVE) + alarm_msix_id;
		vxge_hw_vpath_msix_unmask(vpath->handle, msix_id);
	}
}

/*
 * vxge_vpath_intr_disable
 * @vdev: pointer to vdev
 * @vp_id: vpath for which to disable the interrupts
 *
 * Disables the interrupts for the vpath
*/
void vxge_vpath_intr_disable(struct vxgedev *vdev, int vp_id)
{
	struct __vxge_hw_device  *hldev;
	int msix_id;
	struct vxge_vpath *vpath = &vdev->vpaths[vp_id];

	hldev = (struct __vxge_hw_device *)pci_get_drvdata(vdev->pdev);

	vxge_hw_vpath_wait_receive_idle(hldev, vdev->vpaths[vp_id].device_id);

	vxge_hw_vpath_intr_disable(vpath->handle);

	if (vdev->config.intr_type == INTA)
		vxge_hw_vpath_inta_mask_tx_rx(vpath->handle);
	else {
		msix_id = vpath->device_id * VXGE_HW_VPATH_MSIX_ACTIVE;
		vxge_hw_vpath_msix_mask(vpath->handle, msix_id);
		vxge_hw_vpath_msix_mask(vpath->handle, msix_id + 1);

		/* disable the alarm vector */
		msix_id = (vpath->handle->vpath->hldev->first_vp_id *
			VXGE_HW_VPATH_MSIX_ACTIVE) + VXGE_ALARM_MSIX_ID;
		vxge_hw_vpath_msix_mask(vpath->handle, msix_id);
	}
}

/*
 * vxge_reset_vpath
 * @vdev: pointer to vdev
 * @vp_id: vpath to reset
 *
 * Resets the vpath
*/
static int vxge_reset_vpath(struct vxgedev *vdev, int vp_id)
{
	enum vxge_hw_status status = VXGE_HW_OK;
	int ret = 0;

	/* check if device is down already */
	if (unlikely(!is_vxge_card_up(vdev)))
		return 0;

	/* is device reset already scheduled */
	if (test_bit(__VXGE_STATE_RESET_CARD, &vdev->state))
		return 0;

	if (vdev->vpaths[vp_id].handle) {
		if (vxge_hw_vpath_reset(vdev->vpaths[vp_id].handle)
				== VXGE_HW_OK) {
			if (is_vxge_card_up(vdev) &&
				vxge_hw_vpath_recover_from_reset(
					vdev->vpaths[vp_id].handle)
					!= VXGE_HW_OK) {
				vxge_debug_init(VXGE_ERR,
					"vxge_hw_vpath_recover_from_reset"
					"failed for vpath:%d", vp_id);
				return status;
			}
		} else {
			vxge_debug_init(VXGE_ERR,
				"vxge_hw_vpath_reset failed for"
				"vpath:%d", vp_id);
				return status;
		}
	} else
		return VXGE_HW_FAIL;

	vxge_hw_vpath_mtu_set(vdev->vpaths[vp_id].handle, vdev->mtu);
	vxge_restore_vpath_mac_addr(&vdev->vpaths[vp_id]);
	vxge_restore_vpath_vid_table(&vdev->vpaths[vp_id]);
	/* Restore vlan tag strip state */
	vxge_hw_vpath_handle_vlan_tag_strip(vdev->devh,
			vdev->vpaths[vp_id].device_id,
			vdev->vpaths[vp_id].ring.rx_vlan_stripped);

	/* Enable all broadcast */
	vxge_hw_vpath_bcast_enable(vdev->vpaths[vp_id].handle);

	if (vdev->all_multi_flg) {
		status =
			vxge_hw_vpath_mcast_enable(vdev->vpaths[vp_id].handle);
		if (status != VXGE_HW_OK)
			vxge_debug_init(VXGE_ERR,
				"%s:%d Enabling multicast failed",
				__func__, __LINE__);
	}

	if (vdev->prev_promisc_flg)
		vxge_hw_vpath_promisc_enable(vdev->vpaths[vp_id].handle);

	/* Enable the interrupts */
	vxge_vpath_intr_enable(vdev, vp_id);

	smp_wmb();

	/* Enable the flow of traffic through the vpath */
	vxge_hw_vpath_enable(vdev->vpaths[vp_id].handle);

	smp_wmb();
	vxge_hw_vpath_rx_doorbell_init(vdev->vpaths[vp_id].handle);
	vdev->vpaths[vp_id].ring.last_status = VXGE_HW_OK;

	/* Vpath reset done */
	clear_bit(vp_id, &vdev->vp_reset);

	/* Start the vpath queue */
	vxge_wake_tx_queue(&vdev->vpaths[vp_id].fifo, NULL);

	return ret;
}

static int do_vxge_reset(struct vxgedev *vdev, int event)
{
	enum vxge_hw_status status;
	int ret = 0, vp_id, i = 0;

	vxge_debug_entryexit(VXGE_TRACE, "%s:%d", __func__, __LINE__);

	if ((event == VXGE_LL_FULL_RESET) || (event == VXGE_LL_START_RESET)) {
		/* check if device is down already */
		if (unlikely(!is_vxge_card_up(vdev)))
			return 0;

		/* is reset already scheduled */
		if (test_and_set_bit(__VXGE_STATE_RESET_CARD, &vdev->state))
			return 0;
	}

	if (event == VXGE_LL_FULL_RESET) {
		netif_carrier_off(vdev->ndev);

		/* wait for all the vpath reset to complete */
		for (vp_id = 0; vp_id < vdev->no_of_vpath; vp_id++) {
			while (test_bit(vp_id, &vdev->vp_reset))
				msleep(50);
		}

		/* if execution mode is set to debug, don't reset the adapter */
		if (unlikely(vdev->exec_mode)) {
			vxge_debug_init(VXGE_ERR,
				"%s: execution mode is debug, returning..",
				vdev->ndev->name);
			clear_bit(__VXGE_STATE_CARD_UP, &vdev->state);
			vxge_stop_all_tx_queue(vdev);
			return 0;
		}
	}

	if (event == VXGE_LL_FULL_RESET) {
		vxge_hw_device_wait_receive_idle(vdev->devh);

		vxge_hw_device_intr_disable(vdev->devh);

		switch (vdev->cric_err_event) {
		case VXGE_HW_EVENT_UNKNOWN:
			vxge_stop_all_tx_queue(vdev);
			vxge_debug_init(VXGE_ERR,
				"fatal: %s: Disabling device due to"
				"unknown error",
				vdev->ndev->name);
			ret = -EPERM;
			goto out;
		case VXGE_HW_EVENT_RESET_START:
			break;
		case VXGE_HW_EVENT_RESET_COMPLETE:
		case VXGE_HW_EVENT_LINK_DOWN:
		case VXGE_HW_EVENT_LINK_UP:
		case VXGE_HW_EVENT_ALARM_CLEARED:
		case VXGE_HW_EVENT_ECCERR:
		case VXGE_HW_EVENT_MRPCIM_ECCERR:
			ret = -EPERM;
			goto out;
		case VXGE_HW_EVENT_FIFO_ERR:
		case VXGE_HW_EVENT_VPATH_ERR:
			break;
		case VXGE_HW_EVENT_CRITICAL_ERR:
			vxge_stop_all_tx_queue(vdev);
			vxge_debug_init(VXGE_ERR,
				"fatal: %s: Disabling device due to"
				"serious error",
				vdev->ndev->name);
			/* SOP or device reset required */
			/* This event is not currently used */
			ret = -EPERM;
			goto out;
		case VXGE_HW_EVENT_SERR:
			vxge_stop_all_tx_queue(vdev);
			vxge_debug_init(VXGE_ERR,
				"fatal: %s: Disabling device due to"
				"serious error",
				vdev->ndev->name);
			ret = -EPERM;
			goto out;
		case VXGE_HW_EVENT_SRPCIM_SERR:
		case VXGE_HW_EVENT_MRPCIM_SERR:
			ret = -EPERM;
			goto out;
		case VXGE_HW_EVENT_SLOT_FREEZE:
			vxge_stop_all_tx_queue(vdev);
			vxge_debug_init(VXGE_ERR,
				"fatal: %s: Disabling device due to"
				"slot freeze",
				vdev->ndev->name);
			ret = -EPERM;
			goto out;
		default:
			break;

		}
	}

	if ((event == VXGE_LL_FULL_RESET) || (event == VXGE_LL_START_RESET))
		vxge_stop_all_tx_queue(vdev);

	if (event == VXGE_LL_FULL_RESET) {
		status = vxge_reset_all_vpaths(vdev);
		if (status != VXGE_HW_OK) {
			vxge_debug_init(VXGE_ERR,
				"fatal: %s: can not reset vpaths",
				vdev->ndev->name);
			ret = -EPERM;
			goto out;
		}
	}

	if (event == VXGE_LL_COMPL_RESET) {
		for (i = 0; i < vdev->no_of_vpath; i++)
			if (vdev->vpaths[i].handle) {
				if (vxge_hw_vpath_recover_from_reset(
					vdev->vpaths[i].handle)
						!= VXGE_HW_OK) {
					vxge_debug_init(VXGE_ERR,
						"vxge_hw_vpath_recover_"
						"from_reset failed for vpath: "
						"%d", i);
					ret = -EPERM;
					goto out;
				}
				} else {
					vxge_debug_init(VXGE_ERR,
					"vxge_hw_vpath_reset failed for "
						"vpath:%d", i);
					ret = -EPERM;
					goto out;
				}
	}

	if ((event == VXGE_LL_FULL_RESET) || (event == VXGE_LL_COMPL_RESET)) {
		/* Reprogram the DA table with populated mac addresses */
		for (vp_id = 0; vp_id < vdev->no_of_vpath; vp_id++) {
			vxge_hw_vpath_mtu_set(vdev->vpaths[vp_id].handle, vdev->mtu);
			vxge_restore_vpath_mac_addr(&vdev->vpaths[vp_id]);
			vxge_restore_vpath_vid_table(&vdev->vpaths[vp_id]);
			vxge_hw_vpath_handle_vlan_tag_strip(
				vdev->devh,
				vdev->vpaths[vp_id].device_id,
				vdev->vpaths[vp_id].ring.rx_vlan_stripped);
		}

		/* enable vpath interrupts */
		for (i = 0; i < vdev->no_of_vpath; i++)
			vxge_vpath_intr_enable(vdev, i);

		netif_carrier_on(vdev->ndev);

		vxge_hw_device_intr_enable(vdev->devh);

		smp_wmb();

		/* Indicate card up */
		set_bit(__VXGE_STATE_CARD_UP, &vdev->state);

		/* Get the traffic to flow through the vpaths */
		for (i = 0; i < vdev->no_of_vpath; i++) {
			vxge_hw_vpath_enable(vdev->vpaths[i].handle);
			smp_wmb();
			vxge_hw_vpath_rx_doorbell_init(vdev->vpaths[i].handle);
		}

		vxge_wake_all_tx_queue(vdev);
	}
	/* configure CI */
	vxge_config_ci_for_tti_rti(vdev);

out:
	vxge_debug_entryexit(VXGE_TRACE,
		"%s:%d  Exiting...", __func__, __LINE__);

	/* Indicate reset done */
	if ((event == VXGE_LL_FULL_RESET) || (event == VXGE_LL_COMPL_RESET))
		clear_bit(__VXGE_STATE_RESET_CARD, &vdev->state);
	return ret;
}

#if (LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 19))
static void vxge_gso_update(unsigned long data)
{
	struct net_device *ndev = (struct net_device *) data;
	struct vxgedev *vdev = (struct vxgedev *)netdev_priv(ndev);
#else
static void vxge_gso_update(struct work_struct *work)
{
	struct vxgedev *vdev =
		container_of(work, struct vxgedev, gso_update_task);
#endif
	int vf_idx;
	u32 vplist[VXGE_HW_MAX_VIRTUAL_PATHS];
	u32 num_vpn, num_vfs, msg_sent = 0;
	enum vxge_hw_status status = VXGE_HW_OK;
	struct __vxge_hw_device *hldev =
			(struct __vxge_hw_device *)pci_get_drvdata(vdev->pdev);

	/* Send out the gso message to the all the functions */
	status = __vxge_hw_device_is_privilaged(vdev->devh->host_type,
						vdev->devh->func_id);
	if (status != VXGE_HW_OK)
		return;

	num_vfs = vxge_get_num_devices(vdev);

	for (vf_idx = 0; vf_idx < num_vfs; vf_idx++) {
		/* Get vpathids associated with VFs */
		status = vxge_get_vpn(vdev, vf_idx, &num_vpn, vplist);
		if (status != VXGE_HW_OK)
			return;

		status = vxge_hw_send_message(hldev,
			0,
			VXGE_HW_MSG_TYPE_SEND_CONFIG_GSO_TO_VF,
			vplist[0],
			hldev->config.vp_config[vplist[0]].vp_prio,
			&msg_sent);
		if (status != VXGE_HW_OK)
			continue;
	}
}

static void vxge_update_svid_bit_array(struct vxgedev *vdev)
{
	int vf_idx, vp_idx, vpath_idx;
	struct __vxge_hw_ring *ring_hw;
	struct __vxge_hw_device *hldev =
			(struct __vxge_hw_device *)pci_get_drvdata(vdev->pdev);
	/* update svlan_id bit array for PF vpath's */
	for (vf_idx = 0; vf_idx < vdev->num_functions; vf_idx++) {
		if (hldev->device_svid[vf_idx] != VXGE_HW_SVLAN_ID_DEFAULT) {
			for(vp_idx = 0; vp_idx < vdev->no_of_vpath; vp_idx++) {
				vpath_idx = vdev->vpaths[vp_idx].device_id;
				ring_hw = hldev->virtual_paths[vpath_idx].ringh;
				vxge_setbitarray(ring_hw->svlan_id,
				hldev->device_svid[vf_idx], 1);
			}
		}
	}
}

#if (LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 19))
static void vxge_svid_update(unsigned long data)
{
	struct net_device *ndev = (struct net_device *) data;
	struct vxgedev *vdev = (struct vxgedev *)netdev_priv(ndev);
#else
static void vxge_svid_update(struct work_struct *work)
{
	struct vxgedev *vdev = container_of(work, struct vxgedev, svid_update_task);
#endif
	int vf_idx, vp_idx;
	u32 vpath_idx, num_vpn, num_vfs, msg_sent = 0;
	u32 vplist[VXGE_HW_MAX_VIRTUAL_PATHS];
	struct vxge_vpath * vpath = NULL;
	enum vxge_hw_status status = VXGE_HW_OK;
	struct __vxge_hw_device *hldev =
			(struct __vxge_hw_device *)pci_get_drvdata(vdev->pdev);
	/* Send out the svid to the all the function */
	status = __vxge_hw_device_is_privilaged(vdev->devh->host_type,
						vdev->devh->func_id);
	if (status != VXGE_HW_OK)
		return;

	num_vfs = vxge_get_num_devices(vdev);

	vxge_update_svid_bit_array(vdev);

	for (vf_idx = 0; vf_idx < num_vfs; vf_idx++) {
		/* Get vpathids associated with VFs */
		status = vxge_get_vpn(vdev, vf_idx, &num_vpn, vplist);
		if (status != VXGE_HW_OK)
			return;
		vpath = &vdev->vpaths[0];

		if (hldev->device_svid[vf_idx] != VXGE_HW_SVLAN_ID_DEFAULT) {
			/* If it is new SVID, del old and add new one */
			if (hldev->device_svid[vf_idx] !=
					hldev->device_svid_prev[vf_idx]) {
				hldev->device_svid_prev[vf_idx] =
						hldev->device_svid[vf_idx];
				for (vp_idx = 0; vp_idx < num_vpn; vp_idx++) {
					vpath_idx = vplist[vp_idx];
					vxge_hw_vpath_vid_delete_vpn(
						vpath->handle,
						hldev->device_svid_prev[vf_idx],
						vpath_idx);
					vxge_hw_vpath_vid_add_vpn(
						vpath->handle,
						hldev->device_svid[vf_idx],
						vpath_idx);
				}
			}
			/* Send the message with SVID always irrespective of
			 * of change in SVID value
			 */
			status = vxge_hw_send_message(hldev, 0,
				VXGE_HW_MSG_TYPE_SEND_SVID_TO_VF, vplist[0],
				hldev->device_svid[vf_idx], &msg_sent);
			if (status != VXGE_HW_OK)
				continue;
		}
	}
}
/*
 * vxge_reset
 * @vdev: pointer to ll device
 *
 * driver may reset the chip on events of serr, eccerr, etc
 */
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 19))
static void vxge_reset(unsigned long data)
{
	struct net_device *ndev = (struct net_device *) data;
	struct vxgedev *vdev = (struct vxgedev *)netdev_priv(ndev);
#else
static void vxge_reset(struct work_struct *work)
{
	struct vxgedev *vdev = container_of(work, struct vxgedev, reset_task);
#endif

	if (!netif_running(vdev->ndev))
		return;

	do_vxge_reset(vdev, VXGE_LL_FULL_RESET);
}

/**
 * vxge_poll - Receive handler when Receive Polling is used.
 * @dev: pointer to the device structure.
 * @budget: Number of packets budgeted to be processed in this iteration.
 *
 * This function comes into picture only if Receive side is being handled
 * through polling (called NAPI in linux). It mostly does what the normal
 * Rx interrupt handler does in terms of descriptor and packet processing
 * but not in an interrupt context. Also it will process a specified number
 * of packets at most in one iteration. This value is passed down by the
 * kernel as the function argument 'budget'.
 */
#ifdef VXGE_NETDEV_POLL
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24))
static int vxge_poll_one_vpath_msix(struct net_device *dev, int *budget)
{
	int org_pkts_to_process, pkt_cnt = 0;
	struct vxgedev *vdev = (struct vxgedev *)netdev_priv(dev);
	struct vxge_ring *ring = &vdev->vpaths[0].ring;

	vxge_debug_entryexit(VXGE_TRACE,
		"%s:%d\n", __func__, __LINE__);

	org_pkts_to_process = *budget;
	if (org_pkts_to_process > dev->quota)
		org_pkts_to_process = dev->quota;

	ring->pkts_to_process = org_pkts_to_process;
	vxge_hw_vpath_poll_rx(ring->handle);
	pkt_cnt = org_pkts_to_process - ring->pkts_to_process;
	if (!ring->pkts_to_process) {
		/* Quota for the current iteration has been met */
		goto no_rx;
	}

	if (!pkt_cnt)
		pkt_cnt = 1;

	dev->quota -= pkt_cnt;
	*budget -= pkt_cnt;

	vxge_netif_do_rx_complete(dev, NULL);

	/* Re enable the Rx interrupts */
	vxge_hw_vpath_msix_unmask(vdev->vpaths[0].handle,
			vdev->vpaths[0].ring.rx_vector_no);

	mmiowb();

	vxge_debug_entryexit(VXGE_TRACE,
		"%s:%d  Exiting...\n", __func__, __LINE__);

	return 0;

no_rx:
	dev->quota -= pkt_cnt;
	*budget -= pkt_cnt;

	vxge_debug_entryexit(VXGE_TRACE,
		"%s:%d  Exiting...\n", __func__, __LINE__);

	return 1;
}

static int vxge_poll_msix(struct net_device *dev, int *budget)
{
	int i;
	struct __vxge_hw_device  *hldev;
	struct vxgedev *vdev;
	struct vxge_ring *ring;
	int org_pkts_to_process, pkt_cnt = 0;
	vdev = (struct vxgedev *)netdev_priv(dev);
	hldev = (struct __vxge_hw_device  *)pci_get_drvdata(vdev->pdev);

	vxge_debug_entryexit(VXGE_TRACE,
		"%s:%d\n", __func__, __LINE__);

	/* Mask all Rx vectors.
	* Note: Only one vpath is enabled in this mode of operation, ie.., i is
	* always zero!! This code is present in the event we enable multiple
	* vpaths in this mode of operation.
	*/
	if (vdev->rx_mask_done == 0) {
		for (i = 0; i < vdev->no_of_vpath; i++)
			if ((i == 0) || (vdev->config.rx_steering_type))
				vxge_hw_vpath_msix_mask(vdev->vpaths[i].handle,
					vdev->vpaths[i].ring.rx_vector_no);
				vdev->rx_mask_done = 1;
				vxge_hw_vpath_msix_clear(vdev->vpaths[i].handle,
					vdev->vpaths[i].ring.rx_vector_no);
				vxge_hw_device_flush_io(hldev);
	}

	org_pkts_to_process = *budget;
	if (org_pkts_to_process > dev->quota)
		org_pkts_to_process = dev->quota;

	for (i = 0; i < vdev->no_of_vpath; i++) {
		ring = &vdev->vpaths[i].ring;
		ring->pkts_to_process = org_pkts_to_process - pkt_cnt;
		vxge_hw_vpath_poll_rx(ring->handle);
		pkt_cnt = org_pkts_to_process - ring->pkts_to_process;
		if (!ring->pkts_to_process) {
			/* Quota for the current iteration has been met */
			goto no_rx;
		}
	}

	if (!pkt_cnt)
		pkt_cnt = 1;

	dev->quota -= pkt_cnt;
	*budget -= pkt_cnt;

	vxge_netif_do_rx_complete(dev, NULL);

	/* Re enable the Rx interrupts */
	for (i = 0; i < vdev->no_of_vpath; i++)
		if ((i == 0) || (vdev->config.rx_steering_type))
			vxge_hw_vpath_msix_unmask(vdev->vpaths[i].handle,
				vdev->vpaths[i].ring.rx_vector_no);

	vdev->rx_mask_done = 0;

	mmiowb();

	vxge_debug_entryexit(VXGE_TRACE,
		"%s:%d  Exiting...\n", __func__, __LINE__);

	return 0;

no_rx:
	dev->quota -= pkt_cnt;
	*budget -= pkt_cnt;

	vxge_debug_entryexit(VXGE_TRACE,
		"%s:%d  Exiting...\n", __func__, __LINE__);

	return 1;
}

static int vxge_poll_inta(struct net_device *dev, int *budget)
{
	int i;
	struct __vxge_hw_device  *hldev;
	struct vxgedev *vdev = (struct vxgedev *)netdev_priv(dev);
	struct vxge_ring *ring;
	int org_pkts_to_process, pkt_cnt = 0;

	hldev = (struct __vxge_hw_device  *)pci_get_drvdata(vdev->pdev);

	vxge_debug_entryexit(VXGE_TRACE,
		"%s:%d\n", __func__, __LINE__);

	org_pkts_to_process = *budget;
	if (org_pkts_to_process > dev->quota)
		org_pkts_to_process = dev->quota;

	for (i = 0; i < vdev->no_of_vpath; i++) {
		ring = &vdev->vpaths[i].ring;
		ring->pkts_to_process = org_pkts_to_process - pkt_cnt;
		vxge_hw_vpath_poll_rx(ring->handle);
		pkt_cnt = org_pkts_to_process - ring->pkts_to_process;
		if (!ring->pkts_to_process) {
			/* Quota for the current iteration has been met */
			goto no_rx;
		}
	}

	if (!pkt_cnt)
		pkt_cnt = 1;

	dev->quota -= pkt_cnt;
	*budget -= pkt_cnt;

	vxge_netif_do_rx_complete(dev, NULL);

	VXGE_COMPLETE_ALL_TX(vdev);

	vxge_debug_entryexit(VXGE_TRACE,
		"%s:%d  Exiting...\n", __func__, __LINE__);

		vxge_hw_device_unmask_all(hldev);

	return 0;
no_rx:
	VXGE_COMPLETE_ALL_TX(vdev);

	dev->quota -= pkt_cnt;
	*budget -= pkt_cnt;

	vxge_debug_entryexit(VXGE_TRACE,
		"%s:%d  Exiting...\n", __func__, __LINE__);
	return 1;
}

#else
/**
 * vxge_poll - Receive handler when Receive Polling is used.
 * @dev: pointer to the device structure.
 * @budget: Number of packets budgeted to be processed in this iteration.
 *
 * This function comes into picture only if Receive side is being handled
 * through polling (called NAPI in linux). It mostly does what the normal
 * Rx interrupt handler does in terms of descriptor and packet processing
 * but not in an interrupt context. Also it will process a specified number
 * of packets at most in one iteration. This value is passed down by the
 * kernel as the function argument 'budget'.
 */
static int vxge_poll_msix(struct napi_struct *napi, int budget)
{
	struct vxge_ring *ring =
		container_of(napi, struct vxge_ring, napi);
	int pkts_processed;
	int budget_org = budget;

	ring->budget = budget;
	ring->pkts_processed = 0;
	vxge_hw_vpath_poll_rx(ring->handle);
	pkts_processed = ring->pkts_processed;

	if (ring->pkts_processed < budget_org) {
		vxge_netif_do_rx_complete(ring->ndev, napi);

		/* Re enable the Rx interrupts for the vpath */
		vxge_hw_channel_msix_unmask(
				(struct __vxge_hw_channel *)ring->handle,
				ring->rx_vector_no);
		mmiowb();
	}

	/* We are copying and returning the local variable, in case if after
	 * clearing the msix interrupt above, if the interrupt fires right
	 * away which can preempt this NAPI thread */
	return pkts_processed;
}

static int vxge_poll_inta(struct napi_struct *napi, int budget)
{
	struct vxgedev *vdev = container_of(napi, struct vxgedev, napi);
	int pkts_processed = 0;
	int i;
	int budget_org = budget;
	struct vxge_ring *ring;

	struct __vxge_hw_device  *hldev = (struct __vxge_hw_device *)
		pci_get_drvdata(vdev->pdev);

	for (i = 0; i < vdev->no_of_vpath; i++) {
		ring = &vdev->vpaths[i].ring;
		ring->budget = budget;
		ring->pkts_processed = 0;
		vxge_hw_vpath_poll_rx(ring->handle);
		pkts_processed += ring->pkts_processed;
		budget -= ring->pkts_processed;
		if (budget <= 0)
			break;
	}

	VXGE_COMPLETE_ALL_TX(vdev);

	if (pkts_processed < budget_org) {
		vxge_netif_do_rx_complete(vdev->ndev, napi);
		/* Re enable the Rx interrupts for the ring */

			vxge_hw_device_unmask_all(hldev);

	}

	return pkts_processed;
}
#endif
#endif

#ifdef CONFIG_NET_POLL_CONTROLLER
/**
 * vxge_netpoll - netpoll event handler entry point
 * @dev : pointer to the device structure.
 * Description:
 *      This function will be called by upper layer to check for events on the
 * interface in situations where interrupts are disabled. It is used for
 * specific in-kernel networking tasks, such as remote consoles and kernel
 * debugging over the network (example netdump in RedHat).
 */
static void vxge_netpoll(struct net_device *dev)
{
	struct __vxge_hw_device  *hldev;
	struct vxgedev *vdev;

	vdev = (struct vxgedev *)netdev_priv(dev);
	hldev = (struct __vxge_hw_device  *)pci_get_drvdata(vdev->pdev);

	vxge_debug_entryexit(VXGE_TRACE, "%s:%d", __func__, __LINE__);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 21))
	if (pci_channel_offline(vdev->pdev))
		return;
#endif
	disable_irq(dev->irq);
	vxge_hw_device_clear_tx_rx(hldev);

	VXGE_COMPLETE_ALL_RX(vdev);
	VXGE_COMPLETE_ALL_TX(vdev);

	enable_irq(dev->irq);

	vxge_debug_entryexit(VXGE_TRACE,
		"%s:%d  Exiting...", __func__, __LINE__);
	return;
}
#endif

/* RTH configuration */
static enum vxge_hw_status vxge_rth_configure(struct vxgedev *vdev)
{
	enum vxge_hw_status status = VXGE_HW_OK;
	struct vxge_hw_rth_hash_types hash_types;
	u8 itable[256] = {0}; /* indirection table */
	u8 mtable[256] = {0}; /* CPU to vpath mapping  */
	int index;

	/*
	 * Filling
	 * 	- itable with bucket numbers
	 * 	- mtable with bucket-to-vpath mapping
	 */
	for (index = 0; index < (1 << vdev->config.rth_bkt_sz); index++) {
		itable[index] = index;
		mtable[index] = index % vdev->no_of_vpath;
	}

	/* set indirection table, bucket-to-vpath mapping */
	status = vxge_hw_vpath_rts_rth_itable_set(vdev->vp_handles,
						vdev->no_of_vpath,
						mtable, itable,
						vdev->config.rth_bkt_sz);
	if (status != VXGE_HW_OK) {
		vxge_debug_init(VXGE_ERR,
			"RTH indirection table configuration failed "
			"for vpath:%d", vdev->vpaths[0].device_id);
		return status;
	}

	/* Fill RTH hash types */
	hash_types.hash_type_tcpipv4_en	  = vdev->config.rth_hash_type_tcpipv4;
	hash_types.hash_type_ipv4_en	  = vdev->config.rth_hash_type_ipv4;
	hash_types.hash_type_tcpipv6_en   = vdev->config.rth_hash_type_tcpipv6;
	hash_types.hash_type_ipv6_en	  = vdev->config.rth_hash_type_ipv6;
	hash_types.hash_type_tcpipv6ex_en =
					vdev->config.rth_hash_type_tcpipv6ex;
	hash_types.hash_type_ipv6ex_en	  = vdev->config.rth_hash_type_ipv6ex;

	/*
	 * Because the itable_set() method uses the active_table field
	 * for the target virtual path the RTH config should be updated
	 * for all VPATHs. The h/w only uses the lowest numbered VPATH
	 * when steering frames.
	 */
	 for (index = 0; index < vdev->no_of_vpath; index++) {
		status = vxge_hw_vpath_rts_rth_set(
				vdev->vpaths[index].handle,
				vdev->config.rth_algorithm,
				&hash_types,
				vdev->config.rth_bkt_sz);
		 if (status != VXGE_HW_OK) {
			vxge_debug_init(VXGE_ERR,
				"RTH configuration failed for vpath:%d",
				vdev->vpaths[index].device_id);
			return status;
		 }
	 }

	return status;
}

int vxge_mac_list_add(struct vxge_vpath *vpath, struct macInfo *mac)
{
	struct vxge_mac_addrs *new_mac_entry;
	u8 *mac_address = NULL;

	if (vpath->mac_addr_cnt >= VXGE_MAX_LEARN_MAC_ADDR_CNT) {
		vxge_debug_init(VXGE_ERR,
			"%s:vxge_mac_list_add: Already have %d addresses",
			VXGE_DRIVER_NAME, vpath->mac_addr_cnt);
		return TRUE;
	}

	new_mac_entry = kzalloc(sizeof(struct vxge_mac_addrs), GFP_ATOMIC);
	if (!new_mac_entry) {
		vxge_debug_mem(VXGE_ERR,
			"%s: memory allocation failed",
			VXGE_DRIVER_NAME);
		return FALSE;
	}

	list_add(&new_mac_entry->item, &vpath->mac_addr_list);

	/* Copy the new mac address to the list */
	mac_address = (u8 *)&new_mac_entry->macaddr;
	memcpy(mac_address, mac->macaddr, ETH_ALEN);

	new_mac_entry->send_to_nw = mac->send_to_nw;
	new_mac_entry->origin = mac->origin;
	vpath->mac_addr_cnt++;

	/* Is this a multicast address */
	if (0x01 & mac->macaddr[0])
		vpath->mcast_addr_cnt++;

	return TRUE;
}

/* Add a mac address to DA table */
enum vxge_hw_status vxge_add_mac_addr(struct vxgedev *vdev, struct macInfo *mac)
{
	enum vxge_hw_status status = VXGE_HW_OK;
	struct vxge_vpath *vpath;

	vpath = &vdev->vpaths[mac->vpath_no];
	status = vxge_hw_vpath_mac_addr_add_vpn(vpath->handle, mac->macaddr,
					mac->macmask,
					VXGE_HW_VPATH_MAC_ADDR_ADD_DUPLICATE,
					mac->vpath_no, mac->send_to_nw);
	if (status != VXGE_HW_OK) {
		vxge_debug_init(VXGE_ERR,
			"DA config add entry failed for vpath:%d",
			vpath->device_id);
	} else
		if (FALSE == vxge_mac_list_add(vpath, mac)) {
			vxge_debug_init(VXGE_ERR, "%s: vxge_mac_list_add: "
					"returned Error", VXGE_DRIVER_NAME);
			status = -EPERM;
		}

	return status;
}

int vxge_mac_list_del(struct vxge_vpath *vpath, struct macInfo *mac)
{
	struct list_head *entry, *next;
	u64 del_mac = 0;
	u8 *mac_address = (u8 *) (&del_mac);

	/* Copy the mac address to delete from the list */
	memcpy(mac_address, mac->macaddr, ETH_ALEN);

	list_for_each_safe(entry, next, &vpath->mac_addr_list) {
		if (((struct vxge_mac_addrs *)entry)->macaddr == del_mac) {

			list_del(entry);
			kfree((struct vxge_mac_addrs *)entry);
			vpath->mac_addr_cnt--;

			/* Is this a multicast address */
			if (0x01 & mac->macaddr[0])
				vpath->mcast_addr_cnt--;
			return TRUE;
		}
	}

	return FALSE;
}
/* delete a mac address from DA table */
enum vxge_hw_status vxge_del_mac_addr(struct vxgedev *vdev, struct macInfo *mac)
{
	enum vxge_hw_status status = VXGE_HW_OK;
	struct vxge_vpath *vpath;

	vpath = &vdev->vpaths[mac->vpath_no];

	status = vxge_hw_vpath_mac_addr_del_vpn(vpath->handle, mac->macaddr,
						mac->macmask,
						vpath->handle->vpath->vp_id);
	if (status != VXGE_HW_OK) {

	} else {

		vxge_mac_list_del(vpath, mac);

	}
	return status;
}

/* list all mac addresses from DA table */
enum vxge_hw_status
static vxge_search_mac_addr_in_da_table(struct vxge_vpath *vpath,
					struct macInfo *mac)
{
	enum vxge_hw_status status = VXGE_HW_OK;
	unsigned char macmask[ETH_ALEN];
	unsigned char macaddr[ETH_ALEN];

	status = vxge_hw_vpath_mac_addr_get_vpn(vpath->handle,
				macaddr, macmask,
				vpath->handle->vpath->vp_id);
	if (status != VXGE_HW_OK) {
		vxge_debug_init(VXGE_ERR,
			"DA config list entry failed for vpath:%d",
			vpath->device_id);
		return status;
	}

	while (memcmp(mac->macaddr, macaddr, ETH_ALEN)) {

		status = vxge_hw_vpath_mac_addr_get_next_vpn(vpath->handle,
				macaddr, macmask,
				vpath->handle->vpath->vp_id);
		if (status != VXGE_HW_OK)
			break;
	}

	return status;
}

/* Store all vlan ids from the list to the vid table */
enum vxge_hw_status vxge_restore_vpath_vid_table(struct vxge_vpath *vpath)
{
	enum vxge_hw_status status = VXGE_HW_OK;
	struct vxgedev *vdev = vpath->vdev;
	u16 vid;

	if (vdev->vlgrp && vpath->is_open) {

		for (vid = 0; vid < VLAN_N_VID; vid++) {
			if (!vlan_group_get_device(vdev->vlgrp, vid))
				continue;
			/* Add these vlan to the vid table */
			status = vxge_hw_vpath_vid_add_vpn(vpath->handle, vid,
					vpath->handle->vpath->vp_id);
		}
	}

	return status;
}

/* Store all mac addresses from the list to the DA table */
enum vxge_hw_status vxge_restore_vpath_mac_addr(struct vxge_vpath *vpath)
{
	enum vxge_hw_status status = VXGE_HW_OK;
	struct macInfo mac_info;
	u8 *mac_address = NULL;
	struct list_head *entry, *next;
	struct __vxge_hw_device  *hldev;
	struct vxgedev *vdev = vpath->vdev;

	hldev = (struct __vxge_hw_device  *) pci_get_drvdata(vdev->pdev);

	memset(&mac_info, 0, sizeof(struct macInfo));

	if (vpath->is_open) {
		list_for_each_safe(entry, next, &vpath->mac_addr_list) {
			mac_address =
				(u8 *)&
				((struct vxge_mac_addrs *)entry)->macaddr;
			memcpy(mac_info.macaddr, mac_address, ETH_ALEN);
			/* does this mac address already exist in da table? */
			status = vxge_search_mac_addr_in_da_table(vpath,
				&mac_info);
			if (status != VXGE_HW_OK) {
				/* Add this mac address to the DA table */
				status = vxge_hw_vpath_mac_addr_add_vpn(
					vpath->handle, mac_info.macaddr,
					mac_info.macmask,
					VXGE_HW_VPATH_MAC_ADDR_ADD_DUPLICATE,
					vpath->handle->vpath->vp_id,
					((struct vxge_mac_addrs *)
					entry)->send_to_nw);
				if (status != VXGE_HW_OK) {
					vxge_debug_init(VXGE_ERR,
					    "DA add entry failed for vpath:%d",
					    vpath->device_id);
				}
			}
		}
		if ((vdev->catch_basin_mode) &&
		    (vpath->device_id == hldev->first_vp_id)) {

			/* Re-enable the catch basin */
			vxge_debug_tx(VXGE_TRACE,
				      "%s: Re-enabling catch-basin mode\n",
				      VXGE_DRIVER_NAME);
			status = vxge_hw_change_catch_basin_mode(hldev,
					VXGE_HW_CATCH_BASIN_MODE_ENABLE);
			if (status != VXGE_HW_OK) {
				vxge_debug_tx(VXGE_ERR,
					"%s: Unable to set the function"
					" %d in catch-basin mode",
					VXGE_DRIVER_NAME, hldev->func_id);
				vdev->catch_basin_mode =
					VXGE_HW_CATCH_BASIN_MODE_DISABLE;
			} else {
				vxge_debug_tx(VXGE_TRACE,
				"%s: catch basin mode set for function %d",
				VXGE_DRIVER_NAME, hldev->func_id);
			}
		}
	}

	return status;
}

/* reset vpaths */
enum vxge_hw_status vxge_reset_all_vpaths(struct vxgedev *vdev)
{
	int i;
	enum vxge_hw_status status = VXGE_HW_OK;

	for (i = 0; i < vdev->no_of_vpath; i++)
		if (vdev->vpaths[i].handle) {
			if (vxge_hw_vpath_reset(vdev->vpaths[i].handle)
					== VXGE_HW_OK) {
				if (is_vxge_card_up(vdev) &&
					vxge_hw_vpath_recover_from_reset(
						vdev->vpaths[i].handle)
						!= VXGE_HW_OK) {
					vxge_debug_init(VXGE_ERR,
						"vxge_hw_vpath_recover_"
						"from_reset failed for vpath: "
						"%d", i);
					return status;
				}
			} else {
				vxge_debug_init(VXGE_ERR,
					"vxge_hw_vpath_reset failed for "
					"vpath:%d", i);
					return status;
			}
		}
	return status;
}

/* close vpaths */
void vxge_close_vpaths(struct vxgedev *vdev, int index)
{
	int i;

	for (i = index; i < vdev->no_of_vpath; i++) {
		if (vdev->vpaths[i].handle && vdev->vpaths[i].is_open) {
			vxge_hw_vpath_close(vdev->vpaths[i].handle);
			vdev->stats.vpaths_open--;
		}
		vdev->vpaths[i].is_open = 0;
		vdev->vpaths[i].handle  = NULL;
	}
}

static
void vxge_configure_interrupt_moderation(struct vxgedev *vdev)
{
	struct __vxge_hw_device  *hldev;
	u32 vp_id = 0;
	struct vxge_hw_vp_config *vcfg;
	int i;

	hldev = (struct __vxge_hw_device  *)pci_get_drvdata(vdev->pdev);

	for (i = 0; i < vdev->no_of_vpath; i++) {
		vp_id = vdev->vpaths[i].device_id;
		vcfg = &hldev->config.vp_config[vp_id];
		if (!vdev->titan1) {
			vcfg->tti.uec_a = TTI_T1A_TX_UFC_A;
			vcfg->tti.uec_b = TTI_T1A_TX_UFC_B;
			vcfg->tti.uec_c = TTI_T1A_TX_UFC_C(vdev->mtu);
			vcfg->tti.uec_d = TTI_T1A_TX_UFC_D(vdev->mtu);
			vcfg->rti.urange_a = RTI_T1A_RX_URANGE_A;
			vcfg->rti.urange_b = RTI_T1A_RX_URANGE_B;
			vcfg->rti.urange_c = RTI_T1A_RX_URANGE_C;
			vcfg->tti.rtimer_val = VXGE_T1A_TTI_RTIMER_VAL;
#if 0
			if (hldev->config.vp_config[vp_id].vp_prio ==
								PRIORITY_0) {
				vcfg->tti.uec_a = TTI_TX_UFC_A_0;
				vcfg->tti.uec_b = TTI_TX_UFC_B_0;
				vcfg->tti.uec_c = (TTI_TX_UFC_C_0 +
					((VXGE_HW_MAX_MTU - (vdev->mtu))/93));
				vcfg->tti.uec_d = (TTI_TX_UFC_D_0 +
					((VXGE_HW_MAX_MTU - (vdev->mtu))/37));
				vcfg->rti.uec_a = RTI_RX_UFC_A_0;
				vcfg->rti.uec_b = RTI_RX_UFC_B_0;
				vcfg->rti.uec_c = RTI_RX_UFC_C_0;
				vcfg->rti.uec_d = RTI_RX_UFC_D_0;
				vcfg->tti.rtimer_val =
						VXGE_T1A_TTI_RTIMER_PRI0_VAL;
			}else if (hldev->config.vp_config[vp_id].vp_prio ==
								PRIORITY_1) {
				vcfg->tti.uec_a = TTI_TX_UFC_A_1;
				vcfg->tti.uec_b = TTI_TX_UFC_B_1;
				vcfg->tti.uec_c = (TTI_TX_UFC_C_1 +
					((VXGE_HW_MAX_MTU - (vdev->mtu))/93));
				vcfg->tti.uec_d = (TTI_TX_UFC_D_1 +
					((VXGE_HW_MAX_MTU - (vdev->mtu))/37));
				vcfg->rti.uec_a = RTI_RX_UFC_A_1;
				vcfg->rti.uec_b = RTI_RX_UFC_B_1;
				vcfg->rti.uec_c = RTI_RX_UFC_C_1;
				vcfg->rti.uec_d = RTI_RX_UFC_D_1;
				vcfg->tti.rtimer_val =
						VXGE_T1A_TTI_RTIMER_PRI1_VAL;
			}else if (hldev->config.vp_config[vp_id].vp_prio ==
								PRIORITY_2) {
				vcfg->tti.uec_a = TTI_TX_UFC_A_2;
				vcfg->tti.uec_b = TTI_TX_UFC_B_2;
				vcfg->tti.uec_c = (TTI_TX_UFC_C_2 +
					((VXGE_HW_MAX_MTU - (vdev->mtu))/93));
				vcfg->tti.uec_d = (TTI_TX_UFC_D_2 +
					((VXGE_HW_MAX_MTU - (vdev->mtu))/37));
				vcfg->rti.uec_a = RTI_RX_UFC_A_2;
				vcfg->rti.uec_b = RTI_RX_UFC_B_2;
				vcfg->rti.uec_c = RTI_RX_UFC_C_2;
				vcfg->rti.uec_d = RTI_RX_UFC_D_2;
				vcfg->tti.rtimer_val =
						VXGE_T1A_TTI_RTIMER_PRI2_VAL;
			}else if (hldev->config.vp_config[vp_id].vp_prio ==
								PRIORITY_3) {
				vcfg->tti.uec_a = TTI_TX_UFC_A_3;
				vcfg->tti.uec_b = TTI_TX_UFC_B_3;
				vcfg->tti.uec_c = (TTI_TX_UFC_C_3 +
					((VXGE_HW_MAX_MTU - (vdev->mtu))/93));
				vcfg->tti.uec_d = (TTI_TX_UFC_D_3 +
					((VXGE_HW_MAX_MTU - (vdev->mtu))/37));
				vcfg->rti.uec_a = RTI_RX_UFC_A_3;
				vcfg->rti.uec_b = RTI_RX_UFC_B_3;
				vcfg->rti.uec_c = RTI_RX_UFC_C_3;
				vcfg->rti.uec_d = RTI_RX_UFC_D_3;
				vcfg->tti.rtimer_val =
						VXGE_T1A_TTI_RTIMER_PRI3_VAL;
			}
#endif
			vcfg->tti.ltimer_val = VXGE_T1A_TTI_LTIMER_VAL;
		}
	}

	if ((vdev->config.lro_enable) &&
		(vdev->config.lro_enable != VXGE_HW_GRO_ENABLE)) {
		int size;

		if (vdev->titan1)
			size = MAX_LRO_PACKETS;
		else
			size = MAX_T1A_LRO_PACKETS;

		/* Initialize max aggregatable pkts per session based on MTU */
		vdev->config.lro_max_aggr_per_sess =
				(vdev->config.lro_max_bytes - 1) / vdev->mtu;

		if (vdev->config.lro_max_aggr_per_sess < MIN_LRO_PACKETS)
			vdev->config.lro_max_aggr_per_sess = MIN_LRO_PACKETS;

		if (vdev->config.lro_max_aggr_per_sess > size)
			vdev->config.lro_max_aggr_per_sess = size;
	}
}

/* open vpaths */
int vxge_open_vpaths(struct vxgedev *vdev)
{
	enum vxge_hw_status status, priv_status;
	int i;
	u32 vp_id = 0;
	struct vxge_hw_vpath_attr attr;
	struct vxge_hw_vp_config *vcfg;
	struct __vxge_hw_device  *hldev;

	hldev = (struct __vxge_hw_device  *)pci_get_drvdata(vdev->pdev);

	priv_status = __vxge_hw_device_is_privilaged(vdev->devh->host_type,
						vdev->devh->func_id);

	vxge_configure_interrupt_moderation(vdev);

	for (i = 0; i < vdev->no_of_vpath; i++) {
		vcfg = &hldev->config.vp_config[vdev->vpaths[i].device_id];
		vxge_assert(vdev->vpaths[i].is_configured);
		attr.vp_id = vdev->vpaths[i].device_id;
		attr.fifo_attr.callback = vxge_xmit_compl;
		attr.fifo_attr.txdl_term = vxge_tx_term;
		attr.fifo_attr.per_txdl_space = sizeof(struct vxge_tx_priv);
		attr.fifo_attr.userdata = (void *)&vdev->vpaths[i].fifo;

		attr.ring_attr.callback = vxge_rx_1b_compl;
		attr.ring_attr.rxd_init = vxge_rx_initial_replenish;
		attr.ring_attr.rxd_term = vxge_rx_term;
		attr.ring_attr.per_rxd_space = sizeof(struct vxge_rx_priv);
		attr.ring_attr.userdata = (void *)&vdev->vpaths[i].ring;

		vdev->vpaths[i].ring.ndev = vdev->ndev;
		vdev->vpaths[i].ring.pdev = vdev->pdev;
		status = vxge_hw_vpath_open(vdev->devh, &attr,
				&(vdev->vpaths[i].handle));
		if (status == VXGE_HW_OK) {
			vdev->vpaths[i].fifo.handle =
			    (struct __vxge_hw_fifo *)attr.fifo_attr.userdata;
			vdev->vpaths[i].ring.handle =
			    (struct __vxge_hw_ring *)attr.ring_attr.userdata;

			vdev->vpaths[i].fifo.tx_steering_type =
				vdev->config.tx_steering_type;
#if !defined(VXGE_LLTX)
			if (vdev->config.tx_steering_type)
				vdev->vpaths[i].fifo.txq =
					netdev_get_tx_queue(vdev->ndev, i);
			else
				vdev->vpaths[i].fifo.txq =
					netdev_get_tx_queue(vdev->ndev, 0);
#endif /* LLTX */
			vdev->vpaths[i].fifo.ndev = vdev->ndev;
			vdev->vpaths[i].fifo.pdev = vdev->pdev;
			vdev->vpaths[i].fifo.indicate_max_pkts =
				vdev->config.fifo_indicate_max_pkts;
			vdev->vpaths[i].fifo.tx_vector_no = 0;
        		vdev->vpaths[i].fifo.interrupt_count = 0;
			vdev->vpaths[i].fifo.jiffies = jiffies;
			vdev->vpaths[i].fifo.handle->rtimer =
						VXGE_T1A_TTI_RTIMER_VAL;
			vdev->vpaths[i].fifo.handle->btimer =
						VXGE_TTI_BTIMER_VAL;

			vdev->vpaths[i].ring.aggr_ack =
				vdev->config.aggr_ack;
			vdev->vpaths[i].ring.rx_vector_no = 0;
			vdev->vpaths[i].ring.rx_csum = vdev->rx_csum;
			vdev->vpaths[i].ring.napi_enable =
				vdev->config.napi_enable;
			vdev->vpaths[i].ring.intr_type =
				vdev->config.intr_type;
			vdev->vpaths[i].ring.promisc_en =
				(promisc_en && !priv_status) ?
				VXGE_HW_PROM_MODE_ENABLE:
				VXGE_HW_PROM_MODE_DISABLE;
			vdev->vpaths[i].is_open = 1;
			vdev->vp_handles[i] = vdev->vpaths[i].handle;
			vdev->vpaths[i].ring.lro_enable =
						vdev->config.lro_enable;
			vdev->vpaths[i].ring.handle->btimer =
				(vcfg->rti.btimer_val * 272)/1000;
        		vdev->vpaths[i].ring.interrupt_count = 0;
			vdev->vpaths[i].ring.jiffies = jiffies;
			vdev->vpaths[i].ring.rti_ci = 0;
			if (!vdev->titan1) {
				vdev->vpaths[i].ring.adaptive_intr_coalescing =
				vdev->vpaths[i].fifo.adaptive_intr_coalescing =
					intr_adapt;

				if (low_latency && (vcfg->vp_prio
					== VXGE_HW_VPATH_PRIORITY_HIGH))
					vdev->vpaths[i].fifo.
						adaptive_intr_coalescing = 0;
			}
			vdev->vpaths[i].ring.handle->rxd_qword_limit =
				(vdev->mtu > 8000) ? 4 :
				((vdev->mtu > 4000) ? 8 : 16);

			vdev->stats.vpaths_open++;
		} else {
			vdev->stats.vpath_open_fail++;
			vxge_debug_init(VXGE_ERR,
				"%s: vpath: %d failed to open "
				"with status: %d",
			    vdev->ndev->name, vdev->vpaths[i].device_id,
				status);
			vxge_close_vpaths(vdev, 0);
			return -EPERM;
		}

		if ((vdev->config.lro_enable) && (vdev->config.lro_enable !=
			VXGE_HW_GRO_ENABLE))
			 vxge_hw_vpath_set_lro_sg_size(vdev->vpaths[i].handle,
					vdev->config.lro_max_aggr_per_sess);
		vp_id =
		  ((struct __vxge_hw_vpath_handle *)vdev->vpaths[i].handle)->
		  vpath->vp_id;
		vdev->vpaths_deployed |= vxge_mBIT(vp_id);
	}
	return VXGE_HW_OK;
}

/**
 *  adaptive_coalesce_tx_interrupts - Changes the interrupt coalescing
 *  if the interrupts are not within a range
 *  @fifo: pointer to transmit fifo structure
 *  Description: The function changes boundary timer and restriction timer
 *  value depends on the traffic
 *  Return Value: None
 */
static void adaptive_coalesce_tx_interrupts(struct vxge_fifo *fifo)
{
	if (!fifo->adaptive_intr_coalescing)
		return;

	fifo->interrupt_count++;
	if (jiffies > fifo->jiffies + HZ/100) {
		struct __vxge_hw_fifo *hw_fifo = fifo->handle;
		u32 timer = hw_fifo->rtimer;

		fifo->jiffies = jiffies;
		if ((fifo->interrupt_count > VXGE_T1A_MAX_TX_INTERRUPT_COUNT) &&
			(timer != VXGE_TTI_RTIMER_ADAPT_VAL)) {
				hw_fifo->rtimer = VXGE_TTI_RTIMER_ADAPT_VAL;
				vxge_hw_vpath_dynamic_tti_rtimer_set(hw_fifo);

		} else if (timer != 0) {
				hw_fifo->rtimer = 0;
				vxge_hw_vpath_dynamic_tti_rtimer_set(hw_fifo);
		}
		fifo->interrupt_count = 0;
	}
}
/**
 *  adaptive_coalesce_rx_interrupts - Changes the interrupt coalescing
 *  if the interrupts are not within a range
 *  @ring: pointer to receive ring structure
 *  Description: The function increases of decreases the packet counts within
 *  the ranges of traffic utilization, if the interrupts due to this ring are
 *  not within a fixed range.
 *  Return Value: Nothing
 */
static void adaptive_coalesce_rx_interrupts(struct vxge_ring *ring)
{
	if (!ring->adaptive_intr_coalescing)
		return;

	ring->interrupt_count++;
	if (jiffies > ring->jiffies + HZ/100) {
		struct __vxge_hw_ring *hw_ring = ring->handle;
		u32 timer = hw_ring->rtimer;

		ring->jiffies = jiffies;
		if (ring->interrupt_count > VXGE_T1A_MAX_INTERRUPT_COUNT) {
			if (timer != VXGE_RTI_RTIMER_ADAPT_VAL) {
				hw_ring->rtimer = VXGE_RTI_RTIMER_ADAPT_VAL;
				vxge_hw_vpath_dynamic_rti_rtimer_set(hw_ring);
			}
		} else {
			if (timer != 0) {
				hw_ring->rtimer = 0;
				vxge_hw_vpath_dynamic_rti_rtimer_set(hw_ring);
			}
		}
		ring->interrupt_count = 0;
	}
}

/*
 *  vxge_do_isr_napi
 *  @irq: the irq of the device.
 *  @dev_id: a void pointer to the hldev structure of the Titan device
 *  @ptregs: pointer to the registers pushed on the stack.
 *
 *  This function is the ISR handler of the device when napi is enabled. It
 *  identifies the reason for the interrupt and calls the relevant service
 *  routines.
 */
irqreturn_t vxge_do_isr_napi(int irq, void *dev_id)
{
	struct vxgedev *vdev = (struct vxgedev *) dev_id;
	struct net_device *dev;
	struct __vxge_hw_device *hldev;
	u64 reason;
	enum vxge_hw_status status;

	vxge_debug_intr(VXGE_TRACE, "%s:%d", __func__, __LINE__);

	dev = vdev->ndev;
	hldev = (struct __vxge_hw_device *) pci_get_drvdata(vdev->pdev);

	VXGE_CHECK_PCI_CHANNEL_OFFLINE(vdev->pdev);

	if (unlikely(!is_vxge_card_up(vdev)))
		return IRQ_HANDLED;

	status = vxge_hw_device_begin_irq(hldev, vdev->exec_mode,
			&reason);
	if (status == VXGE_HW_OK) {
		int i;

		vxge_hw_device_mask_all(hldev);

		if (reason &
			VXGE_HW_TITAN_GENERAL_INT_STATUS_VPATH_TRAFFIC_INT(
			vdev->vpaths_deployed >>
			(64 - VXGE_HW_MAX_VIRTUAL_PATHS))) {

			vxge_hw_device_clear_tx_rx(hldev);
			/* Adding barrier to make sure that clearing of
			 * interrupts happens before unmask of
			 * interrupts in napi handler
			 */
			mmiowb();
			vxge_netif_do_rx_schedule(dev, &vdev->napi);
			for (i = 0; i < vdev->no_of_vpath; i++)
				adaptive_coalesce_rx_interrupts(
					&vdev->vpaths[i].ring);
			vxge_debug_intr(VXGE_TRACE,
				"%s:%d  Exiting...", __func__, __LINE__);
			return IRQ_HANDLED;
		} else
			vxge_hw_device_unmask_all(hldev);
	} else if (unlikely((status == VXGE_HW_ERR_VPATH) ||
		(status == VXGE_HW_ERR_CRITICAL) ||
		(status == VXGE_HW_ERR_FIFO))) {
		vxge_hw_device_mask_all(hldev);
		vxge_hw_device_flush_io(hldev);
		return IRQ_HANDLED;
	} else if (unlikely(status == VXGE_HW_ERR_SLOT_FREEZE))
		return IRQ_HANDLED;

	vxge_debug_intr(VXGE_TRACE, "%s:%d  Exiting...", __func__, __LINE__);
	return IRQ_NONE;
}
/*
 *  vxge_do_isr
 *  @irq: the irq of the device.
 *  @dev_id: a void pointer to the hldev structure of the Titan device
 *  @ptregs: pointer to the registers pushed on the stack.
 *
 *  This function is the ISR handler of the device. It identifies the reason
 *  for the interrupt and calls the relevant service routines.
 */
irqreturn_t vxge_do_isr(int irq, void *dev_id)
{
	struct __vxge_hw_device  *hldev;
	struct vxgedev *vdev = (struct vxgedev *) dev_id;
	struct net_device *dev;
	enum vxge_hw_status status;
	u64 reason;

	vxge_debug_intr(VXGE_TRACE,
		"%s:%d\n", __func__, __LINE__);
	dev = vdev->ndev;
	hldev = (struct __vxge_hw_device *) pci_get_drvdata(vdev->pdev);

	VXGE_CHECK_PCI_CHANNEL_OFFLINE(vdev->pdev);

	if (unlikely(!is_vxge_card_up(vdev)))
		return IRQ_HANDLED;

	status = vxge_hw_device_begin_irq(hldev, vdev->exec_mode,
						&reason);
	if (status == VXGE_HW_OK) {
		int i;

		vxge_hw_device_mask_all(hldev);

		if (reason &
			VXGE_HW_TITAN_GENERAL_INT_STATUS_VPATH_TRAFFIC_INT(
			vdev->vpaths_deployed >>
			(64 - VXGE_HW_MAX_VIRTUAL_PATHS))) {

			vxge_hw_device_clear_tx_rx(hldev);
			VXGE_COMPLETE_ALL_RX(vdev);
			VXGE_COMPLETE_ALL_TX(vdev);
			for (i = 0; i < vdev->no_of_vpath; i++)
				adaptive_coalesce_rx_interrupts(
					&vdev->vpaths[i].ring);
			vxge_hw_device_unmask_all(hldev);
			vxge_debug_intr(VXGE_TRACE,
				"%s:%d  Exiting...\n", __func__, __LINE__);
			return IRQ_HANDLED;
		} else
			vxge_hw_device_unmask_all(hldev);
	} else if (unlikely((status == VXGE_HW_ERR_VPATH) ||
		(status == VXGE_HW_ERR_CRITICAL) ||
		(status == VXGE_HW_ERR_FIFO))) {
		vxge_hw_device_mask_all(hldev);
		vxge_hw_device_flush_io(hldev);
		return IRQ_HANDLED;
	} else if (unlikely(status == VXGE_HW_ERR_SLOT_FREEZE))
		return IRQ_HANDLED;

	vxge_debug_intr(VXGE_TRACE, "%s:%d  Exiting...\n", __func__, __LINE__);
	return IRQ_NONE;
}

#ifdef CONFIG_PCI_MSI

irqreturn_t
vxge_do_tx_msix_handle(int irq, void *dev_id)
{
	struct vxge_fifo *fifo = (struct vxge_fifo *)dev_id;

	adaptive_coalesce_tx_interrupts(fifo);

        vxge_hw_channel_msix_mask((struct __vxge_hw_channel *)fifo->handle,
                fifo->tx_vector_no);

        vxge_hw_channel_msix_clear((struct __vxge_hw_channel *)fifo->handle,
                fifo->tx_vector_no);

	VXGE_COMPLETE_VPATH_TX(fifo);

        vxge_hw_channel_msix_unmask((struct __vxge_hw_channel *)fifo->handle,
                fifo->tx_vector_no);

        mmiowb();

	return IRQ_HANDLED;
}

irqreturn_t
vxge_do_rx_msix_handle(int irq, void *dev_id)
{
	struct vxge_ring *ring = (struct vxge_ring *)dev_id;

	adaptive_coalesce_rx_interrupts(ring);

	vxge_hw_channel_msix_mask((struct __vxge_hw_channel *)ring->handle,
		ring->rx_vector_no);

	vxge_hw_channel_msix_clear((struct __vxge_hw_channel *)ring->handle,
		ring->rx_vector_no);

	vxge_hw_vpath_poll_rx(ring->handle);

	vxge_hw_channel_msix_unmask((struct __vxge_hw_channel *)ring->handle,
		ring->rx_vector_no);

	mmiowb();

	return IRQ_HANDLED;
}

irqreturn_t
vxge_do_rx_msix_napi_handle(int irq, void *dev_id)
{
	struct vxge_ring *ring = (struct vxge_ring *)dev_id;

	adaptive_coalesce_rx_interrupts(ring);

	vxge_hw_channel_msix_mask((struct __vxge_hw_channel *)ring->handle,
		ring->rx_vector_no);

	vxge_hw_channel_msix_clear((struct __vxge_hw_channel *)ring->handle,
		ring->rx_vector_no);

#ifdef VXGE_NETDEV_POLL
	vxge_netif_do_rx_schedule(ring->ndev, &ring->napi);
#endif
	return IRQ_HANDLED;
}

irqreturn_t
vxge_do_alarm_msix_handle(int irq, void *dev_id)
{
	int i;
	enum vxge_hw_status status;
	struct vxge_vpath *vpath = (struct vxge_vpath *)dev_id;
	struct vxgedev *vdev = vpath->vdev;
	int msix_id = (vpath->handle->vpath->vp_id *
		VXGE_HW_VPATH_MSIX_ACTIVE) + VXGE_ALARM_MSIX_ID;

	for (i = 0; i < vdev->no_of_vpath; i++) {

		/* Reduce the chance of loosing alarm interrupts by masking
		 * the vector. A pending bit will be set if an alarm is
		 * generated and on unmask the interrupt will be fired.
		 */
		vxge_hw_vpath_msix_mask(vdev->vpaths[i].handle, msix_id);
		vxge_hw_vpath_msix_clear(vdev->vpaths[i].handle, msix_id);
		mmiowb();

		status = vxge_hw_vpath_alarm_process(vdev->vpaths[i].handle,
			vdev->exec_mode);
		if (status == VXGE_HW_OK) {
			vxge_hw_vpath_msix_unmask(vdev->vpaths[i].handle,
						msix_id);
			mmiowb();
			continue;
		}

		vxge_debug_intr(VXGE_ERR,
			"%s: vxge_hw_vpath_alarm_process failed %x ",
			VXGE_DRIVER_NAME, status);
	}
	return IRQ_HANDLED;
}

static int vxge_alloc_msix(struct vxgedev *vdev)
{
	int j, i, ret = 0;
	int msix_intr_vect = 0, temp;
	vdev->intr_cnt = 0;
start:
	/* Tx/Rx MSIX Vectors count */
	vdev->intr_cnt = vdev->no_of_vpath * 2;

	/* Alarm MSIX Vectors count */
	vdev->intr_cnt++;

	vdev->entries = kzalloc(vdev->intr_cnt * sizeof(struct msix_entry),
						GFP_KERNEL);
	if (!vdev->entries) {
		vxge_debug_init(VXGE_ERR,
			"%s: memory allocation failed",
			VXGE_DRIVER_NAME);
		ret = -ENOMEM;
		goto alloc_entries_failed;
	}

	vdev->vxge_entries = kzalloc(vdev->intr_cnt * sizeof(struct vxge_msix_entry),
							GFP_KERNEL);
	if (!vdev->vxge_entries) {
		vxge_debug_init(VXGE_ERR, "%s: memory allocation failed",
			VXGE_DRIVER_NAME);
		ret = -ENOMEM;
		goto alloc_vxge_entries_failed;
	}

	for (i = 0, j = 0; i < vdev->no_of_vpath; i++) {

		msix_intr_vect = i * VXGE_HW_VPATH_MSIX_ACTIVE;

		/* Initialize the fifo vector */
		vdev->entries[j].entry = msix_intr_vect;
		vdev->vxge_entries[j].entry = msix_intr_vect;
		vdev->vxge_entries[j].in_use = 0;
		j++;

		/* Initialize the ring vector */
		vdev->entries[j].entry = msix_intr_vect + 1;
		vdev->vxge_entries[j].entry = msix_intr_vect + 1;
		vdev->vxge_entries[j].in_use = 0;
		j++;
	}

	/* Initialize the alarm vector */
	vdev->entries[j].entry = VXGE_ALARM_MSIX_ID;
	vdev->vxge_entries[j].entry = VXGE_ALARM_MSIX_ID;
	vdev->vxge_entries[j].in_use = 0;

	ret = pci_enable_msix(vdev->pdev, vdev->entries, vdev->intr_cnt);

	if (ret > 0) {
		vxge_debug_init(VXGE_ERR,
			"%s: MSI-X enable failed for %d vectors, ret: %d",
			VXGE_DRIVER_NAME, vdev->intr_cnt, ret);
		if ((max_config_vpath != VXGE_USE_DEFAULT) || (ret < 3)) {
			ret = -ENODEV;
			goto enable_msix_failed;
		}

		kfree(vdev->entries);
		kfree(vdev->vxge_entries);

		/* Try with less no of vector by reducing no of vpaths count */
		temp = (ret - 1)/2;
		vxge_close_vpaths(vdev, temp);
		vdev->no_of_vpath = temp;
		goto start;
	} else if (ret < 0) {
		ret = -ENODEV;
		goto enable_msix_failed;
	}

	return 0;

enable_msix_failed:
	kfree(vdev->vxge_entries);
alloc_vxge_entries_failed:
	kfree(vdev->entries);
alloc_entries_failed:
	return ret;
}

static int vxge_enable_msix(struct vxgedev *vdev)
{

	int i, ret = 0;
	/* 0 - Tx, 1 - Rx  */
	int tim_msix_id[4] = {0, 1, 0, 0};

	vdev->intr_cnt = 0;

	/* allocate msix vectors */
	ret = vxge_alloc_msix(vdev);
	if (!ret) {
		for (i = 0; i < vdev->no_of_vpath; i++) {

			/* If fifo or ring are not enabled
			   the MSIX vector for that should be set to 0
			   Hence initializing this array to all 0s.
			*/
			vdev->vpaths[i].ring.rx_vector_no =
				(vdev->vpaths[i].device_id *
					VXGE_HW_VPATH_MSIX_ACTIVE) + 1;

                        vdev->vpaths[i].fifo.tx_vector_no =
                                (vdev->vpaths[i].device_id *
                                        VXGE_HW_VPATH_MSIX_ACTIVE);

			vxge_hw_vpath_msix_set(
				vdev->vpaths[i].handle,
				tim_msix_id, VXGE_ALARM_MSIX_ID);
		}
	}

	return ret;
}

static void vxge_rem_msix_isr(struct vxgedev *vdev)
{
	int intr_cnt;

	for (intr_cnt = 0; intr_cnt < (vdev->no_of_vpath * 2 + 1);
		intr_cnt++) {
		if (vdev->vxge_entries[intr_cnt].in_use) {

			vxge_synchronize_irq(vdev->entries[intr_cnt].vector);

			free_irq(vdev->entries[intr_cnt].vector,
				vdev->vxge_entries[intr_cnt].arg);
			vdev->vxge_entries[intr_cnt].in_use = 0;
		}
	}

	kfree(vdev->entries);
	kfree(vdev->vxge_entries);
	vdev->entries = NULL;
	vdev->vxge_entries = NULL;

	if (vdev->config.intr_type == MSI_X) {
		pci_disable_msix(vdev->pdev);

	}
}

#endif

static void vxge_rem_isr(struct vxgedev *vdev)
{
	struct __vxge_hw_device  *hldev;
	hldev = (struct __vxge_hw_device  *) pci_get_drvdata(vdev->pdev);

#ifdef CONFIG_PCI_MSI
	if (vdev->config.intr_type == MSI_X) {
		vxge_rem_msix_isr(vdev);
	} else
#endif
	if (

	(vdev->config.intr_type == INTA)) {
		vxge_synchronize_irq(vdev->pdev->irq);
		free_irq(vdev->pdev->irq, vdev);
	}
}

static int vxge_add_isr(struct vxgedev *vdev)
{
	struct vxge_fifo *fifo;
	struct __vxge_hw_fifo *hw_fifo;
	int ret = 0;

#ifdef CONFIG_PCI_MSI
	int msix_idx = 0;
	int vp_idx = 0, intr_idx = 0, intr_cnt = 0, irq_req = 0;
	int pci_fun = PCI_FUNC(vdev->pdev->devfn);

	if (vdev->config.intr_type == MSI_X)
		ret = vxge_enable_msix(vdev);

	if (ret) {
		vxge_debug_init(VXGE_ERR,
		"%s: Enabling MSI-X Failed", VXGE_DRIVER_NAME);
		vxge_debug_init(VXGE_ERR,
			"%s: Defaulting to INTA", VXGE_DRIVER_NAME);
		vdev->config.intr_type = INTA;
	}

	if (vdev->config.intr_type == MSI_X) {
		for (intr_idx = 0;
		     intr_idx < (vdev->no_of_vpath *
			VXGE_HW_VPATH_MSIX_ACTIVE); intr_idx++) {

			msix_idx = intr_idx % VXGE_HW_VPATH_MSIX_ACTIVE;
			irq_req = 0;

			switch (msix_idx) {
			case 0:
				snprintf(vdev->desc[intr_cnt], VXGE_INTR_STRLEN,
					"%s:vxge:MSI-X %d - Tx - fn:%d vpath:%d",
					vdev->ndev->name,
					vdev->entries[intr_cnt].entry,
					pci_fun, vp_idx);
				ret = request_irq(
				    vdev->entries[intr_cnt].vector,
					vxge_tx_msix_handle, 0,
					vdev->desc[intr_cnt],
					&vdev->vpaths[vp_idx].fifo);
					vdev->vxge_entries[intr_cnt].arg =
						&vdev->vpaths[vp_idx].fifo;
				irq_req = 1;
				break;
			case 1:
				snprintf(vdev->desc[intr_cnt], VXGE_INTR_STRLEN,
					"%s:vxge:MSI-X %d - Rx - fn:%d vpath:%d",
					vdev->ndev->name,
					vdev->entries[intr_cnt].entry,
					pci_fun, vp_idx);
				ret = request_irq(
				    vdev->entries[intr_cnt].vector,
					vdev->config.napi_enable ?
					vxge_rx_msix_napi_handle :
					vxge_rx_msix_handle, 0,
					vdev->desc[intr_cnt],
					&vdev->vpaths[vp_idx].ring);
					vdev->vxge_entries[intr_cnt].arg =
						&vdev->vpaths[vp_idx].ring;
				irq_req = 1;
				break;
			}

			if (ret) {
				vxge_debug_init(VXGE_ERR,
					"%s: vxge:"
					"MSIX - %d Registration failed",
					vdev->ndev->name, intr_cnt);
				vxge_rem_msix_isr(vdev);
				vdev->config.intr_type = INTA;
				vxge_debug_init(VXGE_ERR,
					"%s: vxge: Defaulting to INTA",
					vdev->ndev->name);
				goto INTA_MODE;
			}

			if (irq_req) {
				/* We requested for this msix interrupt */
				vdev->vxge_entries[intr_cnt].in_use = 1;
				msix_idx +=  vdev->vpaths[vp_idx].device_id *
					VXGE_HW_VPATH_MSIX_ACTIVE;
				vxge_hw_vpath_msix_unmask(
					vdev->vpaths[vp_idx].handle,
					msix_idx);
				intr_cnt++;
			}

			/* Point to the next vpath handler */
			if (((intr_idx + 1) % VXGE_HW_VPATH_MSIX_ACTIVE == 0)
				&& (vp_idx < (vdev->no_of_vpath - 1)))
					vp_idx++;
		}

		intr_cnt = vdev->no_of_vpath * 2;
		snprintf(vdev->desc[intr_cnt], VXGE_INTR_STRLEN,
			"%s:vxge:MSI-X %d - Alarm - fn:%d",
			vdev->ndev->name,
			vdev->entries[intr_cnt].entry,
			pci_fun);
		/* For Alarm interrupts */
		ret = request_irq(vdev->entries[intr_cnt].vector,
				vxge_alarm_msix_handle, 0,
				vdev->desc[intr_cnt],
				&vdev->vpaths[0]);
		if (ret) {
			vxge_debug_init(VXGE_ERR,
				"%s:vxge:MSIX - %d Registration failed",
				vdev->ndev->name, intr_cnt);
			vxge_rem_msix_isr(vdev);
			vdev->config.intr_type = INTA;
			vxge_debug_init(VXGE_ERR,
				"%s: Defaulting to INTA",
				vdev->ndev->name);
			goto INTA_MODE;
		}

		msix_idx = (vdev->vpaths[0].handle->vpath->vp_id *
			VXGE_HW_VPATH_MSIX_ACTIVE) + VXGE_ALARM_MSIX_ID;

		vxge_hw_vpath_msix_unmask(vdev->vpaths[0].handle,
			msix_idx);

		vdev->vxge_entries[intr_cnt].in_use = 1;
		vdev->vxge_entries[intr_cnt].arg = &vdev->vpaths[0];
	}
INTA_MODE:
#endif

	if (vdev->config.intr_type == INTA) {
		/* Only PF can run with INTA */
		if (is_sriov(vdev->config.device_hw_info.function_mode) &&
			(VXGE_HW_OK !=
			__vxge_hw_device_is_privilaged(
				vdev->config.device_hw_info.host_type,
				vdev->config.device_hw_info.func_id))) {
				vxge_debug_init(VXGE_ERR,
					"%s: SRIOV requires MSI-X support."
					, vdev->ndev->name);
				return -ENODEV;
		}

		vxge_hw_device_set_intr_type(vdev->devh,
			VXGE_HW_INTR_MODE_IRQLINE);
		fifo= &vdev->vpaths[0].fifo;
		hw_fifo = fifo->handle;
		vxge_hw_vpath_tti_ci_set(hw_fifo);

		snprintf(vdev->desc[0], VXGE_INTR_STRLEN,
			"%s:vxge:INTA", vdev->ndev->name);
		ret = request_irq((int) vdev->pdev->irq,
			vdev->config.napi_enable ? vxge_isr_napi : vxge_isr,
			IRQF_SHARED, vdev->desc[0], vdev);
		if (ret) {
			vxge_debug_init(VXGE_ERR,
				"%s %s-%d: ISR registration failed",
				VXGE_DRIVER_NAME, "IRQ", vdev->pdev->irq);
			return -ENODEV;
		}
		vxge_debug_init(VXGE_TRACE,
			"new %s-%d line allocated",
			"IRQ", vdev->pdev->irq);
	}

	return VXGE_HW_OK;
}

static void vxge_poll_vp_reset(unsigned long data)
{
	struct vxgedev *vdev = (struct vxgedev *)data;
	enum vxge_hw_status status;
	int i, j = 0;

	for (i = 0; i < vdev->no_of_vpath; i++) {
		if (test_bit(i, &vdev->vp_reset)) {
			vxge_reset_vpath(vdev, i);
			j++;
		}
	}
	/* Age the MAC Addresses every 5 min*/
	if (vdev->catch_basin_mode == TRUE)
		vxge_age_mac(vdev);

	if (j && (vdev->config.intr_type != MSI_X)) {
		vxge_hw_device_unmask_all(vdev->devh);
		vxge_hw_device_flush_io(vdev->devh);
	}

	status = __vxge_hw_device_is_privilaged(vdev->devh->host_type,
						vdev->devh->func_id);
	if (status == VXGE_HW_OK) {
		if (!(++vdev->svid_upd_sch_count % 20)) {
			schedule_work(&vdev->svid_update_task);
			schedule_work(&vdev->gso_update_task);
		}
	}

	mod_timer(&vdev->vp_reset_timer, jiffies + HZ / 2);

}

static void vxge_poll_vp_lockup(unsigned long data)
{
	struct vxgedev *vdev = (struct vxgedev *)data;
	int i;
	struct vxge_ring *ring;
	enum vxge_hw_status status = VXGE_HW_OK;

	for (i = 0; i < vdev->no_of_vpath; i++) {
		ring = &vdev->vpaths[i].ring;
		/* Did this vpath received any packets */
		if (ring->stats.prev_rx_frms == ring->stats.rx_frms) {
			status = vxge_hw_vpath_check_leak(ring->handle);

			/* Did it received any packets last time */
			if ((VXGE_HW_FAIL == status) &&
				(VXGE_HW_FAIL == ring->last_status)) {

				/* schedule vpath reset */
				if (!test_and_set_bit(i, &vdev->vp_reset)) {

					/* disable interrupts for this vpath */
					vxge_vpath_intr_disable(vdev, i);

					/* stop the queue for this vpath */
					vxge_stop_tx_queue(&vdev->vpaths[i].
								fifo);
					continue;
				}
			}
		}
		ring->stats.prev_rx_frms = ring->stats.rx_frms;
		ring->last_status = status;
	}

	/* Check every 1 milli second */
	mod_timer(&vdev->vp_lockup_timer, jiffies + HZ / 1000);
}

/* Configure CI */
void vxge_config_ci_for_tti_rti(struct vxgedev *vdev)
{
	int i = 0;
	struct __vxge_hw_ring *hw_ring;
	struct vxge_ring *ring;
	struct __vxge_hw_fifo *hw_fifo;
	struct vxge_fifo *fifo;

	/* Enable CI for RTI */
	if (vdev->config.intr_type == MSI_X) {
		for (i = 0; i < vdev->no_of_vpath; i++) {
			ring = &vdev->vpaths[i].ring;
			hw_ring = ring->handle;
			vxge_hw_vpath_dynamic_rti_ci_set(hw_ring);
		}
	}

	/* Enable CI for TTI */
	for (i = 0; i < vdev->no_of_vpath; i++) {
		fifo = &vdev->vpaths[i].fifo;
		hw_fifo = fifo->handle;
		vxge_hw_vpath_tti_ci_set(hw_fifo);
		/*
		 * For Inta (with or without napi), Set CI ON for only one
		 * vpath. (Have only one free running timer).
		 */
		if ((vdev->config.intr_type == INTA) && (i == 0))
			break;
	}

	return;
}

/**
 * vxge_open
 * @dev: pointer to the device structure.
 *
 * This function is the open entry point of the driver. It mainly calls a
 * function to allocate Rx buffers and inserts them into the buffer
 * descriptors and then enables the Rx part of the NIC.
 * Return value: '0' on success and an appropriate (-)ve integer as
 * defined in errno.h file on failure.
 */
int
vxge_open(struct net_device *dev)
{
	enum vxge_hw_status status;
	struct vxgedev *vdev;
	struct __vxge_hw_fifo *fifo_hw;
	struct vxge_fifo *fifo = NULL;
	struct __vxge_hw_ring *ring_hw;
	struct vxge_ring *ring = NULL;

	struct __vxge_hw_device *hldev;
	struct vxge_vpath *vpath = NULL;
	int ret = 0, i = 0, vp_id = 0, j = 0;
	int vpath_idx, num_vpn;
	u32 vplist[VXGE_HW_MAX_VIRTUAL_PATHS];
	u64 val64;
	vxge_debug_entryexit(VXGE_TRACE,
		"%s: %s:%d", dev->name, __func__, __LINE__);

	vdev = (struct vxgedev *)netdev_priv(dev);
	hldev = (struct __vxge_hw_device *)pci_get_drvdata(vdev->pdev);

	/* make sure you have link off by default every time Nic is
	 * initialized */
	netif_carrier_off(dev);

	/* Mask all device interrupts */
	vxge_hw_device_mask_all(hldev);

	/* Open VPATHs */
	status = vxge_open_vpaths(vdev);
	if (status != VXGE_HW_OK) {
		vxge_debug_init(VXGE_ERR,
			"%s: fatal: Vpath open failed", vdev->ndev->name);
		ret = -EPERM;
		goto out0;
	}

	vdev->mtu = dev->mtu;

	status = vxge_add_isr(vdev);
	if (status != VXGE_HW_OK) {
		vxge_debug_init(VXGE_ERR,
			"%s: fatal: ISR add failed", dev->name);
		ret = -EPERM;
		goto out1;
	}

	for (i = 0; i < vdev->no_of_vpath; i++){
		vp_id = vdev->vpaths[i].device_id;
		vdev->config.napi_weight = NAPI_WEIGHT_0;
#if 0
		switch (hldev->config.vp_config[vp_id].vp_prio) {
		case PRIORITY_0:
				vdev->config.napi_weight = NAPI_WEIGHT_0;
      				break;
		case PRIORITY_1:
				vdev->config.napi_weight = NAPI_WEIGHT_1;
 				break;
		case PRIORITY_2:
				vdev->config.napi_weight = NAPI_WEIGHT_2;
				break;
		case PRIORITY_3:
				vdev->config.napi_weight = NAPI_WEIGHT_3;
				break;
		default:
				vdev->config.napi_weight = NAPI_WEIGHT_0;
				break;
		}
#endif
	}
	/* configure GSO/TSO */
	vxge_config_gso(vdev, dev);

#ifdef VXGE_NETDEV_POLL
	/* Initialize napi */
	if (vdev->config.napi_enable) {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24))
		if (vdev->config.intr_type != MSI_X)
			dev->poll = vxge_poll_inta;
		else if (vdev->no_of_vpath == 1)
			dev->poll = vxge_poll_one_vpath_msix;
		else
			dev->poll = vxge_poll_msix;
		dev->weight = vdev->config.napi_weight;
#else
		if (vdev->config.intr_type != MSI_X) {
			netif_napi_add(dev, &vdev->napi, vxge_poll_inta,
				vdev->config.napi_weight);
			VXGE_NAPI_ENABLE(&vdev->napi);

			for (i = 0; i < vdev->no_of_vpath; i++)
				vdev->vpaths[i].ring.napi_p = &vdev->napi;
		} else {
			for (i = 0; i < vdev->no_of_vpath; i++) {
				netif_napi_add(dev, &vdev->vpaths[i].ring.napi,
				    vxge_poll_msix, vdev->config.napi_weight);
				VXGE_NAPI_ENABLE(&vdev->vpaths[i].ring.napi);
				vdev->vpaths[i].ring.napi_p =
					&vdev->vpaths[i].ring.napi;
			}
		}
#endif
	}
#endif
	/* configure RTH */
	if (vdev->config.rx_steering_type) {
		status = vxge_rth_configure(vdev);
		if (status != VXGE_HW_OK) {
			vxge_debug_init(VXGE_ERR,
				"%s: fatal: RTH configuration failed",
				dev->name);
			ret = -EPERM;
			goto out2;
		}
	}
#ifdef NETIF_F_RXHASH
	printk("%s: Receive Hashing Offload %s\n", dev->name,
	       hldev->config.rth_en ? "enabled" : "disabled");
#endif

	/* set initial mtu before enabling the device */
	for (i = 0; i < vdev->no_of_vpath; i++)
		 vxge_hw_vpath_mtu_set(vdev->vpaths[i].handle, vdev->mtu);

	VXGE_DEVICE_DEBUG_LEVEL_SET(VXGE_TRACE, VXGE_COMPONENT_LL, vdev);
	vxge_debug_init(vdev->level_trace,
		"%s: MTU is %d", vdev->ndev->name, vdev->mtu);
	VXGE_DEVICE_DEBUG_LEVEL_SET(VXGE_ERR, VXGE_COMPONENT_LL, vdev);

	/* Restore the DA, VID table and also
	 * multicast and promiscuous mode states */
	for (i = 0; i < vdev->no_of_vpath; i++) {
		vpath = &vdev->vpaths[i];
		vxge_restore_vpath_mac_addr(vpath);
		vxge_restore_vpath_vid_table(vpath);

		vxge_hw_vpath_handle_vlan_tag_strip(
			vdev->devh,
			vdev->vpaths[i].device_id,
			vdev->vpaths[i].ring.rx_vlan_stripped);

		if (vdev->all_multi_flg) {
			status = vxge_hw_vpath_mcast_enable(vpath->handle);
			if (status != VXGE_HW_OK)
				vxge_debug_init(VXGE_ERR,
					"%s:%d Enabling multicast failed",
					__func__, __LINE__);
		}

		if (vdev->prev_promisc_flg)
			vxge_hw_vpath_promisc_enable(vpath->handle);
	}

	/* Enable first vpath to sniff all unicast/multicast
	 * traffic that's not addressed to them.
	 * We allow promiscuous mode for the PF only.
	 */
	val64 = VXGE_HW_RXMAC_AUTHORIZE_ALL_ADDR_VP(0);

	vxge_hw_mgmt_reg_write(vdev->devh,
		vxge_hw_mgmt_reg_type_mrpcim,
		0,
		(ulong)offsetof(struct vxge_hw_mrpcim_reg,
			rxmac_authorize_all_addr),
		val64);

	vxge_hw_mgmt_reg_write(vdev->devh,
		vxge_hw_mgmt_reg_type_mrpcim,
		0,
		(ulong)offsetof(struct vxge_hw_mrpcim_reg,
			rxmac_authorize_all_vid),
		val64);

	/* Update the Svlan ID to hldev structure */
	for (i = 0; i < vdev->num_functions; i++) {
		hldev->device_svid[i] = svlan_id[i];
		hldev->device_svid_prev[i] = svlan_id[i];
	}

	vxge_update_svid_bit_array(vdev);

	hldev->s_vid = svlan_id[hldev->func_id];

	for (i = 0; i < vdev->no_of_vpath; i++) {

		vpath = &vdev->vpaths[i];
		if (!vpath->is_open)
			continue;

		if (vdev->vlan_tag_strip ==
			VXGE_HW_VPATH_RPA_STRIP_VLAN_TAG_ENABLE) {
			vdev->vpaths[i].ring.rx_vlan_stripped = TRUE;
			vxge_hw_vpath_handle_vlan_tag_strip(vdev->devh,
					vdev->vpaths[i].device_id,
					vdev->vpaths[i].ring.rx_vlan_stripped);
		} else
			vdev->vpaths[i].ring.rx_vlan_stripped = FALSE;

		/* Updateing the SVID ids to fifo and ring structure */
		fifo = &vdev->vpaths[i].fifo;
		fifo_hw = fifo->handle;
		fifo_hw->s_vid = hldev->s_vid;

		ring = &vdev->vpaths[i].ring;
		ring_hw = ring->handle;
		ring_hw->s_vid = hldev->s_vid;
	}

	/* Enabling Bcast and mcast for all vpath */
	for (i = 0; i < vdev->no_of_vpath; i++) {
		vpath = &vdev->vpaths[i];
		status = vxge_hw_vpath_bcast_enable(vpath->handle);
		if (status != VXGE_HW_OK)
			vxge_debug_init(VXGE_ERR,
				"%s : Can not enable bcast for vpath "
				"id %d", dev->name, i);

		if (vdev->config.rec_all_vid) {
			status = vxge_hw_vpath_all_vid_enable(vpath->handle);
			if (status != VXGE_HW_OK)
				vxge_debug_init(VXGE_ERR,
					"%s : Can not enable all vid for vpath\
					id %d \n", dev->name, i);
		}
	}

	if (vdev->vp_reset_timer.function == NULL)
		vxge_os_timer(vdev->vp_reset_timer,
			vxge_poll_vp_reset, vdev, (HZ/2));
	if (vdev->config.catch_basin_mode ==
			VXGE_CATCH_BASIN_MODE_ALWAYS_ENABLE) {
		status = vxge_hw_change_catch_basin_mode(hldev,
				VXGE_HW_CATCH_BASIN_MODE_ENABLE);
		if (status != VXGE_HW_OK) {
			vxge_debug_tx(VXGE_ERR,
			"%s: Unable to set the function %d in catch-basin mode",
			VXGE_DRIVER_NAME, hldev->func_id);
			ret = -EPERM;
			goto out2;
		}
		vdev->catch_basin_mode = TRUE;
	}

	/*
	 * There is no need to check for RxD leak and RxD lookup due to
	 * bug3618 if Titan 1A is used.
	 */
	if (vdev->titan1) {
		if (vdev->vp_lockup_timer.function == NULL)
			vxge_os_timer(vdev->vp_lockup_timer,
				vxge_poll_vp_lockup, vdev, (HZ/2));
	}

	set_bit(__VXGE_STATE_CARD_UP, &vdev->state);

	smp_wmb();

	if (vxge_hw_device_link_state_get(vdev->devh) == VXGE_HW_LINK_UP) {
		netif_carrier_on(vdev->ndev);
		printk(KERN_NOTICE "%s: Link Up\n", vdev->ndev->name);
		vdev->stats.link_up++;
	}

	status = __vxge_hw_device_is_privilaged(vdev->devh->host_type,
						vdev->devh->func_id);
	if (status != VXGE_HW_OK)
		goto update_vf;

	/* Update the steering table with VID, in the case of PF */
	for (i = 0; i < vdev->num_functions; i++) {

		/* Do not update, if it is deafult value */
		if (svlan_id[i] == VXGE_HW_SVLAN_ID_DEFAULT)
			continue;

		status = vxge_get_vpn(vdev, i, &num_vpn, vplist);
		if (status != VXGE_HW_OK) {
			vxge_debug_init(VXGE_ERR,
				"vxge_get_vpn failed with status:%d for VFID:%d",
				status, i);
			goto out0;
		}

		vpath = &vdev->vpaths[0];

		for (j = 0; j < num_vpn; j++) {
			vpath_idx = vplist[j];
			status = vxge_hw_vpath_vid_add_vpn(vpath->handle,
							hldev->device_svid[i],
							vpath_idx);
			if (status != VXGE_HW_OK) {
				vxge_debug_init(VXGE_ERR,
                                "VLAN ID add entry failed for vpath:%d "
				"err: %d", vpath->device_id, -status);
				goto out0;
			}
		}

	}
	goto skip_update_vf;
update_vf:
	if (hldev->s_vid != VXGE_HW_SVLAN_ID_DEFAULT) {
		for (j = 0; j < vdev->no_of_vpath; j++) {
			vpath = &vdev->vpaths[j];
			if (!vpath->is_open)
				continue;
			status = vxge_hw_vpath_vid_add_vpn(vpath->handle,
					hldev->s_vid,
					vpath->handle->vpath->vp_id);
			if (status != VXGE_HW_OK) {
				vxge_debug_init(VXGE_ERR,
				"VLAN ID add entry failed for vpath:%d err: %d",
				vpath->device_id, -status);
				goto out0;
			}
		}
	}

skip_update_vf:
	vxge_hw_device_intr_enable(vdev->devh);

	smp_wmb();

	for (i = 0; i < vdev->no_of_vpath; i++) {
		vxge_hw_vpath_enable(vdev->vpaths[i].handle);
		smp_wmb();
		vxge_hw_vpath_rx_doorbell_init(vdev->vpaths[i].handle);
	}

	vxge_start_all_tx_queue(vdev);
	status = __vxge_hw_device_is_privilaged(vdev->devh->host_type,
						vdev->devh->func_id);
	if (status == VXGE_HW_OK) {
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 19))
		INIT_WORK(&vdev->svid_update_task,
				(void (*)(void *))vxge_svid_update, vdev->ndev);
		INIT_WORK(&vdev->gso_update_task,
				(void (*)(void *))vxge_gso_update, vdev->ndev);
#else
		INIT_WORK(&vdev->svid_update_task, vxge_svid_update);
		INIT_WORK(&vdev->gso_update_task, vxge_gso_update);
#endif
	}
	/* configure CI */
	vxge_config_ci_for_tti_rti(vdev);

	goto out0;

out2:

	vxge_rem_isr(vdev);

	/* Disable napi */
	if (vdev->config.napi_enable) {
		if (vdev->config.intr_type != MSI_X)
			VXGE_NAPI_DISABLE(&vdev->napi);
		else {
			for (i = 0; i < vdev->no_of_vpath; i++)
				VXGE_NAPI_DISABLE(&vdev->vpaths[i].ring.napi);
		}
	}

out1:

	vxge_close_vpaths(vdev, 0);
out0:
	vxge_debug_entryexit(VXGE_TRACE,
				"%s: %s:%d  Exiting...",
				dev->name, __func__, __LINE__);
	return ret;
}

/* Loop throught the mac address list and delete all the entries */
void vxge_free_mac_add_list(struct vxge_vpath *vpath)
{

	struct list_head *entry, *next;
	if (list_empty(&vpath->mac_addr_list))
		return;

	list_for_each_safe(entry, next, &vpath->mac_addr_list) {
		list_del(entry);
		kfree((struct vxge_mac_addrs *)entry);
	}
}

#ifdef VXGE_NETDEV_POLL
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27))
static void vxge_napi_del_all(struct vxgedev *vdev)
{
	int i;
	if (vdev->config.intr_type != MSI_X)
		netif_napi_del(&vdev->napi);
	else {
		for (i = 0; i < vdev->no_of_vpath; i++)
			netif_napi_del(&vdev->vpaths[i].ring.napi);
	}
	return;
}
#endif
#endif
int do_vxge_close(struct net_device *dev, int do_io)
{
	struct vxgedev *vdev;
	struct __vxge_hw_device *hldev;
	struct vxge_vpath *vpath;
	int i;
	u64 vp_id;

	vxge_debug_entryexit(VXGE_TRACE, "%s: %s:%d",
		dev->name, __func__, __LINE__);

	vdev = (struct vxgedev *)netdev_priv(dev);
	hldev = (struct __vxge_hw_device *) pci_get_drvdata(vdev->pdev);

	if (unlikely(!is_vxge_card_up(vdev)))
		return 0;

	/* If vxge_handle_crit_err task is executing,
	 * wait till it completes. */
	while (test_and_set_bit(__VXGE_STATE_RESET_CARD, &vdev->state))
		msleep(50);

	if (do_io) {
		/* Remove the function 0 from promiscous mode */
		vxge_hw_mgmt_reg_write(vdev->devh,
			vxge_hw_mgmt_reg_type_mrpcim,
			0,
			(ulong)offsetof(struct vxge_hw_mrpcim_reg,
				rxmac_authorize_all_addr),
			0);

		vxge_hw_mgmt_reg_write(vdev->devh,
			vxge_hw_mgmt_reg_type_mrpcim,
			0,
			(ulong)offsetof(struct vxge_hw_mrpcim_reg,
				rxmac_authorize_all_vid),
			0);

		smp_wmb();
	}

	/*
	 * There is no need to check for RxD leak and RxD lookup due to
	 * bug3618 if Titan 1A is used.
	 */
	if (vdev->titan1)
		del_timer_sync(&vdev->vp_lockup_timer);

	del_timer_sync(&vdev->vp_reset_timer);

	if (do_io)
		vxge_hw_device_wait_receive_idle(hldev);

	for (i = 0; i < vdev->no_of_vpath; i++) {
		vp_id = vdev->vpaths[i].device_id;
		spin_lock(&hldev->vp_reg_lock[vp_id]);
	}

	clear_bit(__VXGE_STATE_CARD_UP, &vdev->state);

	for (i = 0; i < vdev->no_of_vpath; i++) {
		vp_id = vdev->vpaths[i].device_id;
		spin_unlock(&hldev->vp_reg_lock[vp_id]);
	}

	/* Disable napi */
	if (vdev->config.napi_enable) {
		if (vdev->config.intr_type != MSI_X)
			VXGE_NAPI_DISABLE(&vdev->napi);
		else {
			for (i = 0; i < vdev->no_of_vpath; i++)
				VXGE_NAPI_DISABLE(&vdev->vpaths[i].ring.napi);
		}
	}

	netif_carrier_off(vdev->ndev);
	printk(KERN_NOTICE "%s: Link Down\n", vdev->ndev->name);
	vxge_stop_all_tx_queue(vdev);

	/* Note that at this point xmit() is stopped by upper layer */
	if (do_io)
		vxge_hw_device_intr_disable(vdev->devh);

	vxge_rem_isr(vdev);

#ifdef VXGE_NETDEV_POLL
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27))
	if (vdev->config.napi_enable)
		vxge_napi_del_all(vdev);
#endif
#endif

	if (is_mf(vdev->config.device_hw_info.function_mode))
		if (vdev->config.intr_type == INTA)
			vxge_hw_device_unmask_all(hldev);

	if (do_io)
		vxge_reset_all_vpaths(vdev);

	/* Delete the svlan_id */
	if (hldev->s_vid != VXGE_HW_SVLAN_ID_DEFAULT) {
		for (i = 0; i < vdev->no_of_vpath; i++) {
			vpath = &vdev->vpaths[i];
			if (!vpath->is_open)
				continue;
			vxge_hw_vpath_vid_delete_vpn(vpath->handle,
					hldev->s_vid,
					vpath->handle->vpath->vp_id);
		}
	}

	vxge_close_vpaths(vdev, 0);

	vdev->catch_basin_mode = VXGE_HW_CATCH_BASIN_MODE_DISABLE;

	vxge_debug_entryexit(VXGE_TRACE,
		"%s: %s:%d  Exiting...", dev->name, __func__, __LINE__);

	clear_bit(__VXGE_STATE_RESET_CARD, &vdev->state);

	return 0;
}

/**
 * vxge_close
 * @dev: device pointer.
 *
 * This is the stop entry point of the driver. It needs to undo exactly
 * whatever was done by the open entry point, thus it's usually referred to
 * as the close function.Among other things this function mainly stops the
 * Rx side of the NIC and frees all the Rx buffers in the Rx rings.
 * Return value: '0' on success and an appropriate (-)ve integer as
 * defined in errno.h file on failure.
 */
int
vxge_close(struct net_device *dev)
{
	do_vxge_close(dev, 1);
	return 0;
}

/**
 * do_vxge_change_mtu
 * @vdev: vxge device pointer.
 * @new_mtu :the new MTU size for the device.
 *
 * Helper function to change MTU size for the device. This function configures
 * the mtu size for the receive mac for each vpath in the function.
 */
static void do_vxge_change_mtu(struct vxgedev *vdev, int new_mtu)
{
	struct vxge_vpath *vpath;
	int i;
	struct __vxge_hw_device  *hldev;

	hldev = (struct __vxge_hw_device  *)pci_get_drvdata(vdev->pdev);

	for (i = 0; i < vdev->no_of_vpath; i++) {
		vpath = &vdev->vpaths[i];

		vxge_configure_interrupt_moderation(vdev);

		vxge_hw_vpath_tim_configure(hldev, vpath->device_id);

		vpath->ring.handle->rxd_qword_limit =
			(vdev->mtu > 8000) ? 4 :
			((vdev->mtu > 4000) ? 8 : 16);

		vxge_config_ci_for_tti_rti(vdev);

		vxge_hw_vpath_mtu_set(vpath->handle, new_mtu);
	}
	return;
}

/**
 * vxge_change_mtu
 * @dev: net device pointer.
 * @new_mtu :the new MTU size for the device.
 *
 * A driver entry point to change MTU size for the device. Before changing
 * the MTU the device must be stopped.
 */
static int vxge_change_mtu(struct net_device *dev, int new_mtu)
{
	struct vxgedev *vdev = netdev_priv(dev);

	vxge_debug_entryexit(vdev->level_trace,
		"%s:%d", __func__, __LINE__);
	if ((new_mtu < VXGE_HW_MIN_MTU) || (new_mtu > VXGE_HW_MAX_MTU)) {
		vxge_debug_init(vdev->level_err,
			"%s: mtu size is invalid", dev->name);
		return -EPERM;
	}

	/* Resetting max_rx_buffer_size to new_mtu size, if it is greater */

	vdev->max_rx_buffer_size = new_mtu;

	dev->mtu = new_mtu;
	vdev->mtu = new_mtu;

	if (!test_and_clear_bit(__VXGE_STATE_CARD_UP, &vdev->state)) {
		/* check if device is down already */
		/* Stored mtu value will be used after device comes up */
		vxge_debug_init(vdev->level_err,
			"%s: device is down on MTU change", dev->name);
		return 0;
	}

	vxge_debug_init(vdev->level_trace,
		"trying to apply new MTU %d", new_mtu);

	do_vxge_change_mtu(vdev, new_mtu);

	/* Indicate card up */
	set_bit(__VXGE_STATE_CARD_UP, &vdev->state);

	vxge_debug_init(vdev->level_trace,
		"%s: MTU changed to %d", vdev->ndev->name, new_mtu);

	vxge_debug_entryexit(vdev->level_trace,
		"%s:%d  Exiting...", __func__, __LINE__);

	return 0;
}

/**
 * vxge_get_stats
 * @dev: pointer to the device structure
 *
 * Updates the device statistics structure. This function updates the device
 * statistics structure in the net_device structure and returns a pointer
 * to the same.
 */
static struct net_device_stats *
vxge_get_stats(struct net_device *dev)
{
	struct vxgedev *vdev;
	struct net_device_stats *net_stats;
	int k;

	vdev = netdev_priv(dev);

	net_stats = &vdev->stats.net_stats;

	memset(net_stats, 0, sizeof(struct net_device_stats));

	for (k = 0; k < vdev->no_of_vpath; k++) {
		net_stats->rx_packets += vdev->vpaths[k].ring.stats.rx_frms;
		net_stats->rx_bytes += vdev->vpaths[k].ring.stats.rx_bytes;
		net_stats->rx_errors += vdev->vpaths[k].ring.stats.rx_errors;
		net_stats->multicast += vdev->vpaths[k].ring.stats.rx_mcast;
		net_stats->rx_dropped +=
			vdev->vpaths[k].ring.stats.rx_dropped;

		net_stats->tx_packets += vdev->vpaths[k].fifo.stats.tx_frms;
		net_stats->tx_bytes += vdev->vpaths[k].fifo.stats.tx_bytes;
		net_stats->tx_errors += vdev->vpaths[k].fifo.stats.tx_errors;
	}

	return net_stats;
}

/* Transfer fw image to adapter 16 bytes at a time */
enum vxge_hw_status
vxge_update_fw_image(struct __vxge_hw_device  *hldev, u8* filebuf, int size)
{
	enum vxge_hw_status status = VXGE_HW_OK;
	u64 data0, data1, steer_ctrl;
	int done = FALSE, ret_code, sec_code, i;
	u32 bytes2skip; /* number of bytes to skip for a skip command */

	/* send upgrade start command */
	data0 = 1; data1 = 0;
	status = vxge_hw_vpath_fw_api(hldev, 0,
			VXGE_HW_FW_UPGRADE_ACTION,
			VXGE_HW_FW_UPGRADE_OFFSET_START,
			VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL_FW_MEMO,
			&data0, &data1, &steer_ctrl);
	if (status != VXGE_HW_OK) {
		vxge_debug_init(VXGE_ERR,
			" %s: Upgrade start cmd failed '%s'.",
			VXGE_DRIVER_NAME, VXGE_FW_FILE_NAME);
		return VXGE_HW_FAIL;
	}

	while ((!done)) {
		data0 = data1 = 0;

		if (size <= 0) {
			vxge_debug_init(VXGE_ERR,
				" %s: Reached EOF no more data '%s'.",
				VXGE_DRIVER_NAME, VXGE_FW_FILE_NAME);
			break;
		}

		/* send 16 bytes at a time */
		for (i = 0; i < VXGE_HW_BYTES_PER_U64; i++)
			data0 |=
			(long long)filebuf[i] << (i * VXGE_HW_BYTES_PER_U64);

		for (i = 0; i < VXGE_HW_BYTES_PER_U64; i++)
			data1 |=
			(long long)filebuf[VXGE_HW_BYTES_PER_U64 + i] <<
				(i * VXGE_HW_BYTES_PER_U64);

		status = vxge_hw_vpath_fw_api(hldev, 0,
			VXGE_HW_FW_UPGRADE_ACTION,
			VXGE_HW_FW_UPGRADE_OFFSET_SEND,
			VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL_FW_MEMO,
			&data0, &data1, &steer_ctrl);
		if (status != VXGE_HW_OK) {
			vxge_debug_init(VXGE_ERR,
				"%s: Upgrade send failed '%s'.",
				VXGE_DRIVER_NAME, VXGE_FW_FILE_NAME);
			return status;
		}

		ret_code = VXGE_HW_UPGRADE_GET_RET_ERR_CODE(data0);
		sec_code = VXGE_HW_UPGRADE_GET_SEC_ERR_CODE(data0);

		switch (ret_code) {
		case VXGE_HW_FW_UPGRADE_OK:
			/* All OK, send next 16 bytes. */
			break;
		case VXGE_HW_FW_UPGRADE_DONE:
			done = TRUE;
			break;
		case VXGE_HW_FW_UPGRADE_ERR:
			switch (sec_code) {
			case VXGE_HW_FW_UPGRADE_ERR_CORRUPT_DATA_1:
			case VXGE_HW_FW_UPGRADE_ERR_CORRUPT_DATA_7:
				printk(KERN_ERR
					"corrupted data from .ncf file\n");
				break;
			case VXGE_HW_FW_UPGRADE_ERR_INV_NCF_FILE_3:
			case VXGE_HW_FW_UPGRADE_ERR_INV_NCF_FILE_4:
			case VXGE_HW_FW_UPGRADE_ERR_INV_NCF_FILE_5:
			case VXGE_HW_FW_UPGRADE_ERR_INV_NCF_FILE_6:
			case VXGE_HW_FW_UPGRADE_ERR_INV_NCF_FILE_8:
				printk(KERN_ERR "invalid .ncf file\n");
				break;
			case VXGE_HW_FW_UPGRADE_ERR_BUFFER_OVERFLOW:
				printk(KERN_ERR "buffer overflow\n");
				break;
			case VXGE_HW_FW_UPGRADE_ERR_FAILED_TO_FLASH:
				printk(KERN_ERR "failed to flash the image\n");
				break;
			case VXGE_HW_FW_UPGRADE_ERR_GENERIC_ERROR_UNKNOWN:
				printk(KERN_ERR
					"generic error. Unknown error type\n");
				break;
			default:
				printk(KERN_ERR
					"generic error. Known error type\n");
				break;
			}
			printk(KERN_ERR "ret_code:0x%x sec_code:0x%x\n",
					ret_code, sec_code);
			status = VXGE_HW_FAIL;
			done = TRUE;
			break;
		case VXGE_FW_UPGRADE_BYTES2SKIP:
			/* skip bytes in the stream */
			bytes2skip = (data0 >> 8) & 0xFFFFFFFF;
			filebuf += bytes2skip;
			break;
		}
		/* point to next 16 bytes */
		filebuf += VXGE_HW_FW_UPGRADE_BLK_SIZE;
		size = size - VXGE_HW_FW_UPGRADE_BLK_SIZE;
	}
	return status;
}

/* configure funtion mode and port changes */
u8 record_persist_config(struct __vxge_hw_device *hldev)
{
	enum vxge_hw_status status;
	u8 commit_req = 0;
	u64 active_config = VXGE_USE_DEFAULT;
	u32 func_mode_curr;
	u32 ports = 0, cfg_port_mode = port_mode;
	u32 cfg_port_behavior = port_behavior;
	u32 fw_version_current = hldev->fw_version;
	u64 data0 = 0, data1 = 0, steer_ctrl = 0;
	u32 fw_memo = VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL_FW_MEMO;

	/* function mode change */
	if (func_mode != VXGE_USE_DEFAULT) {
		status = vxge_hw_get_func_mode(hldev, &func_mode_curr);
		if ((status == VXGE_HW_OK) && (func_mode != func_mode_curr)) {
			status = vxge_hw_change_func_mode(hldev, func_mode);
			printk(KERN_ALERT "%s: Configuration to %s request"
				" %s\n", VXGE_DRIVER_NAME,
				vxge_func_mode_names[func_mode],
				(status == VXGE_HW_FAIL) ?
				"failed" : "succeeded");
			if (status == VXGE_HW_OK) {
				/*
				 * When in MF and DP mode, if user wants to
				 * change to SF, change port_mode to single
				 * port mode.
				 */
				if ((is_mf(func_mode_curr) && (func_mode ==
					VXGE_HW_FUNCTION_MODE_SINGLE_FUNCTION))
					&& ((cfg_port_mode == VXGE_USE_DEFAULT)
					|| (cfg_port_mode !=
					VXGE_HW_DP_NP_MODE_ACTIVE_PASSIVE))) {
					cfg_port_mode =
						VXGE_HW_DP_NP_MODE_SINGLE_PORT;
				}
				commit_req = 1;
			}
		}
	}

	/* l2_switch configuration */
	active_config = VXGE_USE_DEFAULT;
	if (l2_switch != VXGE_USE_DEFAULT) {
		status = vxge_hw_get_active_config(hldev,
			  VXGE_HW_XMAC_NWIF_ActConfig_L2SwitchEnabled,
			  &active_config);
		if ((status == VXGE_HW_OK) && (l2_switch != active_config)) {
			status = vxge_hw_endis_l2_switch(hldev, l2_switch);
			printk(KERN_ALERT
				"%s: L2 switch %s %s\n",
				VXGE_DRIVER_NAME,
				(l2_switch ==
				VXGE_HW_XMAC_NWIF_L2_SWITCH_DISABLE) ? "disable":
				"enable",
				(status == VXGE_HW_FAIL) ?
				"failure" : "success");
			if (status == VXGE_HW_OK)
				commit_req = 1;
		}
	}

	/* Read number of physical ports on the adapter */
	status = __vxge_hw_get_port_cnt(hldev, &ports);
	if ((status != VXGE_HW_OK) || (ports == 1))
		goto commit;

	status = vxge_hw_get_active_config(hldev,
			VXGE_HW_XMAC_NWIF_ActConfig_NWPortMode,
			&active_config);
	if (status != VXGE_HW_OK)
		goto commit;

	/* port_mode configuration */
	if (cfg_port_mode != VXGE_USE_DEFAULT) {
		/* When in SF mode don't allow active/active port_mode */
		if (cfg_port_mode == VXGE_HW_DP_NP_MODE_ACTIVE_ACTIVE ) {
			status = vxge_hw_get_func_mode(hldev, &func_mode_curr);
			if ((status == VXGE_HW_OK) && (func_mode_curr ==
				VXGE_HW_FUNCTION_MODE_SINGLE_FUNCTION)) {
				printk(KERN_ALERT
					"%s: Adapter is in single function "
					"mode. Dual port mode is not allowed\n",
					VXGE_DRIVER_NAME);
				goto exit1;
			}
		}

		if (cfg_port_mode != active_config) {
			status = vxge_hw_set_port_mode(hldev, cfg_port_mode);
			printk(KERN_ALERT
				"%s: Port mode change to %s %s\n",
				VXGE_DRIVER_NAME,
				vxge_port_mode_names[cfg_port_mode],
				(status == VXGE_HW_FAIL) ?
				"failed" : "succeeded");
			if (status != VXGE_HW_OK)
				goto exit1;

			/*
 			 * Configure vpath_mapping for active/active mode only
 			 */
			if (cfg_port_mode ==
				VXGE_HW_DP_NP_MODE_ACTIVE_ACTIVE) {
				status = vxge_hw_config_vpath_map(hldev,
						VXGE_HW_DP_PORT_MAP);
				printk(KERN_ALERT
					"%s: Port map change %s\n",
					VXGE_DRIVER_NAME,
					(status == VXGE_HW_FAIL) ?
					"failed" : "succeeded");
				if (status != VXGE_HW_OK)
					goto exit1;
			}
			commit_req = 1;
			active_config = cfg_port_mode;
		}
	}

	/* port_behavior configurations */
	if (cfg_port_behavior == VXGE_USE_DEFAULT) {
		/* If port behavior is default and not changed by user,
		 * then:
		 *   In active/active mode, set port fail over to NoMove.
		 *   In active/passive mode, set port fail over to Failover
		 *   Failback.
		 *   By definition there is no failover option for single port
		 *   mode and is not configured.
		 */
		if (active_config == VXGE_HW_DP_NP_MODE_ACTIVE_ACTIVE)
			cfg_port_behavior =
				VXGE_HW_XMAC_NWIF_OnFailure_NoMove ;
		else if (active_config == VXGE_HW_DP_NP_MODE_ACTIVE_PASSIVE)
			cfg_port_behavior =
			VXGE_HW_XMAC_NWIF_OnFailure_OtherPortBackOnRestore;
	}

	active_config = VXGE_USE_DEFAULT;
	if (cfg_port_behavior != VXGE_USE_DEFAULT) {
		status = vxge_hw_get_active_config(hldev,
			  VXGE_HW_XMAC_NWIF_ActConfig_BehaviourOnFail,
			  &active_config);
		if ((status == VXGE_HW_OK) &&
		    (cfg_port_behavior != active_config)) {
			status = vxge_hw_set_behavior_on_failure(hldev,
					cfg_port_behavior);
			printk(KERN_ALERT
				"%s: Port behavior change to %s %s\n",
				VXGE_DRIVER_NAME,
				vxge_port_behavior_names[cfg_port_behavior],
				(status == VXGE_HW_FAIL) ?
				"failed" : "succeeded");
			if (status == VXGE_HW_OK)
				commit_req = 1;
			else
				goto exit1;
		}
	}

commit:
	/* commit the changes */
	if (commit_req)
		/* for fw_ver >= 1.5.1 Commit is requried */
		if (fw_version_current >= VXGE_COMMIT_REQ_FW_VER)
			status = vxge_hw_vpath_fw_api(hldev, 0,
					VXGE_HW_FW_API_FUNC_MODE_COMMIT, 0,
					fw_memo, &data0, &data1, &steer_ctrl);
exit1:
	return commit_req;
}

/* firmware upgrade */
static enum vxge_hw_status vxge_fw_upgrade(struct __vxge_hw_device *hldev)
{
	enum vxge_hw_status status = VXGE_HW_OK;
	int ret_code, size, major, minor, build;
	u8 *filebuf;
	u64 data0, data1, steer_ctrl;
	u32 fw_version_current = hldev->fw_version;

#if ((defined(VXGE_KERNEL_FW_UPGRADE)))
	ret_code = request_firmware(&hldev->fw, VXGE_FW_FILE_NAME,
			&hldev->pdev->dev);
	if (ret_code) {
		vxge_debug_init(VXGE_ERR,
			"%s: Failed to load firmware \"%s\" %d",
			VXGE_DRIVER_NAME, VXGE_FW_FILE_NAME, ret_code);
		return VXGE_HW_FAIL;
	}
	size = hldev->fw->size;
	filebuf = (u8 *)hldev->fw->data;
#else
	size = VXGE_HW_FW_BUF_LEN;
	filebuf = (u8 *)VXGE_HW_FW_BUF;
#endif

	/* write firmware image to adapter */
	status = vxge_update_fw_image(hldev, filebuf, size);
	if (status != VXGE_HW_OK) {
		vxge_debug_init(VXGE_ERR,
			"%s: FW image download to adapter failed '%s'.",
			VXGE_DRIVER_NAME, VXGE_FW_FILE_NAME);
		goto exit;
	}

	/* read the target fw version we will be upgrading to */
	status = vxge_hw_upgrade_read_version(hldev, &major,
			&minor, &build);
	if (status != VXGE_HW_OK) {
		vxge_debug_init(VXGE_ERR,
			"%s: Upgrade read version failed '%s'.",
			VXGE_DRIVER_NAME, VXGE_FW_FILE_NAME);
		goto exit;
	}

	/* check if the fw_ver read is below or same as current fw_version */
	if ((fw_upgrade == VXGE_HW_FW_UPGRADE_ALL) &&
		(VXGE_FW_VER(major, minor, build) == fw_version_current)) {
		vxge_debug_init(VXGE_ERR,
			"%s: Adapter already running FW Version"
			" %d.%d.%d aborting commit",
			VXGE_DRIVER_NAME, major, minor, build);
			status = VXGE_HW_FAIL;
			goto exit;
	}

	/* issue commit command */
	status = vxge_hw_vpath_fw_api(hldev, 0,
			VXGE_HW_FW_UPGRADE_ACTION,
			VXGE_HW_FW_UPGRADE_OFFSET_COMMIT,
			VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL_FW_MEMO,
			&data0, &data1, &steer_ctrl);
	if (status != VXGE_HW_OK) {
		vxge_debug_init(VXGE_ERR,
			"%s: Upgrade commit failed '%s'.",
			VXGE_DRIVER_NAME, VXGE_FW_FILE_NAME);
		goto exit;
	}

	ret_code = VXGE_HW_RTS_ACCESS_STEER_CTRL_GET_ACTION(steer_ctrl) & 0x7F;
	if (ret_code != 1) {
		vxge_debug_init(VXGE_ERR,
			"%s: FW commit failed with error code:%d",
			VXGE_DRIVER_NAME, ret_code);
			status = VXGE_HW_FAIL;
			goto exit;
	}

	/* Change function mode, port configurations.
	 * Some of the l2_switch and and port_mode configrurations are not
	 * supported in older firmwares before 1.7.0, allow these configurations
	 * when adapter is in 1.7.0 and above firmware */
	if (fw_version_current >= VXGE_FW_VER(1, 7, 0))
		record_persist_config(hldev);
	else if ((func_mode != VXGE_USE_DEFAULT) ||
		(port_mode != VXGE_USE_DEFAULT) ||
		(port_behavior != VXGE_USE_DEFAULT) ||
		(l2_switch != VXGE_USE_DEFAULT))
		vxge_debug_init(VXGE_ERR, "%s: Configuration parameters are not"
			" applied. Reapply them again after power cycle",
			VXGE_DRIVER_NAME);

exit:
	vxge_release_firmware(hldev->fw);
	return status;
}

enum vxge_hw_status
vxge_config_promisc_mode(struct vxgedev *vdev, int promisc_mode)
{
	enum vxge_hw_status status = VXGE_HW_FAIL;
	int i;
	struct __vxge_hw_device *hldev;
	struct vxge_hw_vpath_reg __iomem *vp_reg;

	hldev = (struct __vxge_hw_device *)pci_get_drvdata(vdev->pdev);
	vp_reg = (struct vxge_hw_vpath_reg __iomem *)hldev->vpath_reg[0];

	if (!(vdev->devh->access_rights & VXGE_HW_DEVICE_ACCESS_RIGHT_MRPCIM))
		goto exit0;

	if (vdev->config.promisc_all_en || vdev->config.promisc_en)
		goto exit0;

	if (promisc_mode) {
		/* Get the current status of L2 switch */
		status = vxge_hw_get_active_config(vdev->devh,
			VXGE_HW_XMAC_NWIF_ActConfig_L2SwitchEnabled,
			&vdev->prev_l2_switch);
		if (status != VXGE_HW_OK)
			goto exit0;

		/* Disable L2 switch */
		if (vdev->prev_l2_switch !=
			VXGE_HW_XMAC_NWIF_L2_SWITCH_DISABLE) {
			status = vxge_hw_endis_l2_switch(vdev->devh,
				VXGE_HW_XMAC_NWIF_L2_SWITCH_DISABLE);
			if (status != VXGE_HW_OK)
				goto exit0;
		}

		/* Enable promiscuous mode */
		for (i = 0; i < vdev->no_of_vpath; i++)
			vxge_hw_vpath_promisc_enable(
				vdev->vpaths[i].handle);
	} else {
		/* Disable promiscuous mode */
		for (i = 0; i < vdev->no_of_vpath; i++)
			vxge_hw_vpath_promisc_disable(
				vdev->vpaths[i].handle);
		/* Restore L2 switch */
		status = vxge_hw_endis_l2_switch(vdev->devh,
			vdev->prev_l2_switch);
	}
exit0:
	return status;
}

enum vxge_hw_status
vxge_config_mirror_veb(struct vxgedev *vdev, int mirror_veb)
{
	enum vxge_hw_status status = VXGE_HW_FAIL;
	int i;
	struct __vxge_hw_device *hldev;
	struct vxge_hw_vpath_reg __iomem *vp_reg;

	hldev = (struct __vxge_hw_device *)pci_get_drvdata(vdev->pdev);
	vp_reg = (struct vxge_hw_vpath_reg __iomem *)hldev->vpath_reg[0];

	if (!(vdev->devh->access_rights & VXGE_HW_DEVICE_ACCESS_RIGHT_MRPCIM))
		goto exit0;

	if (vdev->config.promisc_all_en || vdev->config.promisc_en)
		goto exit0;

	if (mirror_veb) {
		/* Get the current status of L2 switch */
		status = vxge_hw_get_active_config(vdev->devh,
			VXGE_HW_XMAC_NWIF_ActConfig_L2SwitchEnabled,
			&vdev->prev_l2_switch);
		if (status != VXGE_HW_OK)
			goto exit0;

		/* Enable L2 switch */
		if (vdev->prev_l2_switch !=
			VXGE_HW_XMAC_NWIF_L2_SWITCH_ENABLE) {
			status = vxge_hw_endis_l2_switch(vdev->devh,
				VXGE_HW_XMAC_NWIF_L2_SWITCH_ENABLE);
			if (status != VXGE_HW_OK)
				goto exit0;
		}

		/* Enable promiscuous mode */
		for (i = 0; i < vdev->no_of_vpath; i++)
			vxge_hw_vpath_promisc_enable(
				vdev->vpaths[i].handle);
	} else {
		/* Disable promiscuous mode */
		for (i = 0; i < vdev->no_of_vpath; i++)
			vxge_hw_vpath_promisc_disable(
				vdev->vpaths[i].handle);
		/* Restore L2 switch */
		status = vxge_hw_endis_l2_switch(vdev->devh,
			vdev->prev_l2_switch);
	}
exit0:
	return status;
}

/* MAP PF's vpath on other port */
enum vxge_hw_status
vxge_map_pf_vpaths_on_port1(struct vxgedev *vdev, int mirror_mode)
{
	enum vxge_hw_status status = VXGE_HW_FAIL;
	int num_vpn;
	struct __vxge_hw_device *hldev;
	u64 vpath_map, vpath_mask;

	hldev = (struct __vxge_hw_device *)pci_get_drvdata(vdev->pdev);

	if (!(vdev->devh->access_rights & VXGE_HW_DEVICE_ACCESS_RIGHT_MRPCIM))
		goto exit0;

	/* Get current vpath mapping */
	status = vxge_hw_get_active_config(hldev,
		  VXGE_HW_XMAC_NWIF_ActConfig_DualPortPath, &vpath_map);
	if (status != VXGE_HW_OK)
		goto exit0;

	/* Get vpath mask */
	status = __vxge_hw_get_vpath_no(vdev->devh, 0, &num_vpn,
			&vpath_mask);
	if (status != VXGE_HW_OK)
		goto exit0;

	if (mirror_mode)
		vpath_map |= vpath_mask;
	else
		vpath_map &= ~(vpath_mask);

	/* Change port_map */
	status = vxge_hw_config_vpath_map(hldev, vpath_map);
exit0:
	return status;
}

/* This routine configures the adapter in the VEPA mode.
 * Enabling VEPA mode means our HW have to turn OFF our L-2 switch.
 */
enum vxge_hw_status
vxge_config_vepa_mode(struct vxgedev *vdev, int vepa_mode)
{
	enum vxge_hw_status status = VXGE_HW_FAIL;
	struct __vxge_hw_device *hldev;
	struct vxge_hw_vpath_reg __iomem *vp_reg;

	hldev = (struct __vxge_hw_device *)pci_get_drvdata(vdev->pdev);
	vp_reg = (struct vxge_hw_vpath_reg __iomem *)hldev->vpath_reg[0];

	if (!(vdev->devh->access_rights & VXGE_HW_DEVICE_ACCESS_RIGHT_MRPCIM))
		goto exit0;
	if (vepa_mode) {
		/* Get the current status of L2 switch */
		status = vxge_hw_get_active_config(vdev->devh,
			VXGE_HW_XMAC_NWIF_ActConfig_L2SwitchEnabled,
			&vdev->prev_l2_switch);
		if (status != VXGE_HW_OK){
			vxge_debug_init(VXGE_ERR, "%s: "
				"vxge_hw_get_active_config returned failure",
				VXGE_DRIVER_NAME);
			goto exit0;
		}

		/* Disable L2 switch, if it is not already disabled */
		if (vdev->prev_l2_switch !=
			VXGE_HW_XMAC_NWIF_L2_SWITCH_DISABLE) {
			status = vxge_hw_endis_l2_switch(vdev->devh,
					VXGE_HW_XMAC_NWIF_L2_SWITCH_DISABLE);
			if (status != VXGE_HW_OK){
				vxge_debug_init(VXGE_ERR, "%s: "
					"vxge_hw_endis_l2_switch returned "
					" failure", VXGE_DRIVER_NAME);
				goto exit0;
			}
		}
	} else {
		/* Enable L2 switch */
		status = vxge_hw_endis_l2_switch(vdev->devh,
				vdev->prev_l2_switch);
		if (status != VXGE_HW_OK){
			printk("vxge_hw_endis_l2_switch returned failure\n");
			goto exit0;
		}
	}
exit0:
	return status;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30))
static enum vxge_hw_status vxge_timestamp_config(struct vxgedev *vdev, int enable)
{
	enum vxge_hw_status status;
	u64 val64;

	/* Timestamp is passed to the driver via the FCS, therefore we
	 * must disable the FCS stripping by the adapter.  Since this is
	 * required for the driver to load (due to a hardware bug),
	 * there is no need to do anything special here.
	 */

	if (enable)
		val64 = VXGE_HW_XMAC_TIMESTAMP_EN |
			VXGE_HW_XMAC_TIMESTAMP_USE_LINK_ID(0) |
			VXGE_HW_XMAC_TIMESTAMP_INTERVAL(0);
	else
		val64 = 0;

       	status = vxge_hw_mgmt_reg_write(vdev->devh,
					vxge_hw_mgmt_reg_type_mrpcim,
					0,
					offsetof(struct vxge_hw_mrpcim_reg,
						 xmac_timestamp),
					val64);
	vxge_hw_device_flush_io(vdev->devh);
	return status;
}

static int
vxge_hwtstamp_ioctl(struct vxgedev *vdev, struct hwtstamp_config *config)
{
	enum vxge_hw_status status;

	/* reserved for future extensions */
	if (config->flags)
		return -EINVAL;


	/* Transmit HW Timestamp not supported */
	switch (config->tx_type) {
	case HWTSTAMP_TX_OFF:
		break;
	case HWTSTAMP_TX_ON:
	default:
		return -ERANGE;
	}

	switch (config->rx_filter) {
	case HWTSTAMP_FILTER_NONE:
		status = vxge_timestamp_config(vdev, 0);
		if (status != VXGE_HW_OK)
			return -EFAULT;

		vdev->rx_hwts = 0;
		config->rx_filter = HWTSTAMP_FILTER_NONE;
		break;

	case HWTSTAMP_FILTER_ALL:
	case HWTSTAMP_FILTER_SOME:
	case HWTSTAMP_FILTER_PTP_V1_L4_EVENT:
	case HWTSTAMP_FILTER_PTP_V1_L4_SYNC:
	case HWTSTAMP_FILTER_PTP_V1_L4_DELAY_REQ:
	case HWTSTAMP_FILTER_PTP_V2_L4_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_L4_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_L4_DELAY_REQ:
	case HWTSTAMP_FILTER_PTP_V2_L2_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_L2_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_L2_DELAY_REQ:
	case HWTSTAMP_FILTER_PTP_V2_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_DELAY_REQ:

	  printk("vxge_hwtstamp_ioctl() called\n");

		status = vxge_timestamp_config(vdev, 1);
		if (status != VXGE_HW_OK)
			return -EFAULT;

		vdev->rx_hwts = 1;
		config->rx_filter = HWTSTAMP_FILTER_ALL;
		break;

	default:
		 return -ERANGE;
	}

	return 0;
}
#endif

/*
 * vxge_ioctl
 * @dev: Device pointer.
 * @ifr: An IOCTL specefic structure, that can contain a pointer to
 *       a proprietary structure used to pass information to the driver.
 * @cmd: This is used to distinguish between the different commands that
 *       can be passed to the IOCTL functions.
 *
 * Entry point for the Ioctl.
 * This function has support for ethtool, adding multiple MAC addresses on
 * the NIC and some DBG commands for the util tool.
 */
static int vxge_ioctl(struct net_device *dev, struct ifreq *rq, int cmd)
{
	struct vxgedev *vdev = netdev_priv(dev);
	enum vxge_hw_status status;
	vxge_priv_ioctlInfo_t ioctl_info;
	void *arg = (void *)rq->ifr_data;

	vxge_debug_entryexit(VXGE_TRACE,
		"%s:%d\n", __func__, __LINE__);

	if (copy_from_user(&ioctl_info, arg, sizeof(ioctl_info)))
		return -EFAULT;

	switch (cmd) {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30))
	case SIOCSHWTSTAMP: {
		int ret;
		ret = vxge_hwtstamp_ioctl(vdev, arg);
		if (ret)
			return ret;
		break;
	}
#endif
#ifndef SET_ETHTOOL_OPS
	case SIOCETHTOOL:
		return vxge_ethtool(dev, rq);
#endif

	/* Other utility ioctls that can be used */
#ifdef VXGE_TRACE_INTO_CIRCULAR_ARR
	/* Dumping the Trace buffer */
	case SIOCDEVPRIVATE + 15:
	{
		struct vxgedev *vdev = netdev_priv(dev);
		vxge_hw_device_trace_dump(vdev->devh);
		goto exit0;
	}
	/* Reading the Trace buffer */
	case SIOCDEVPRIVATE + 2:
	{
		struct vxgedev *vdev = netdev_priv(dev);
		char *buffer;
		unsigned buf_size = VXGE_HW_DEF_CIRCULAR_ARR;
		unsigned read_length = 0;
		struct tracebufInfo *tbufinfo = (struct tracebufInfo *)
							rq->ifr_data;
		buffer = kmalloc(buf_size, GFP_KERNEL);
		if (buffer == NULL) {
			vxge_debug_init(VXGE_ERR,
				"%s: memory allocation failed",
				VXGE_DRIVER_NAME);
			return  -ENOMEM;
		}
		vxge_hw_device_trace_read(vdev->devh,
			buffer, buf_size,
			&read_length);

		memcpy(tbufinfo->buffer, buffer, read_length);
		tbufinfo->read_length = read_length;

		if (copy_to_user((void *) tbufinfo->buffer,
			(void *) buffer, read_length))
			return -EFAULT;

		kfree(buffer);
		goto exit0;
	}
#endif
	/* ULD config params */
	case SIOCDEVPRIVATE + 7:
	{
		char *buf = NULL;
		int retsize = 0;

		buf = vmalloc(VXGE_DEVCONF_BUFSIZE);
		if (buf == NULL) {
			vxge_debug_init(VXGE_ERR,
				"%s:%d uld config:unable to alloc mem :%d\n",
				 __func__, __LINE__, -ENOMEM);
			return -ENOMEM;
		}
		status = vxge_hw_aux_device_config_read(vdev->devh,
				VXGE_DEVCONF_BUFSIZE,
				buf, &retsize);

		if (status != VXGE_HW_OK) {
			vxge_debug_init(VXGE_ERR,
				"%s:%d device read error:%d\n",
				__func__, __LINE__, status);
			vfree(buf);
			return status;
		}
		if (copy_to_user(arg,
			(void *) buf,
			VXGE_DEVCONF_BUFSIZE)) {
			vfree(buf);
			return -EFAULT;
		}
		vfree(buf);
		goto exit0;
	}
	/* Regs */
	case SIOCDEVPRIVATE + 8:
	{
		char *buf = NULL;
		struct ioctlInfo *io = (struct ioctlInfo *)
					rq->ifr_data;

		buf = vmalloc(VXGE_REG_DUMP_BUFSIZE);
		if (buf == NULL) {
			vxge_debug_init(VXGE_ERR,
				"%s:%d reg dump:unable to alloc mem :%d\n",
				 __func__, __LINE__, -ENOMEM);
			return -ENOMEM;
		}
		/* XXX A note on the params:
			1. reg_type - uspace utility passes the type of reg
			   to dump
			2. size - size of the register set
		*/
		status = vxge_hw_aux_reg_dump(vdev->devh,
				buf,
				io->reg_type,
				io->size);

		if (status != VXGE_HW_OK) {
			vxge_debug_init(VXGE_ERR,
				"%s:%d reg dump error:%d\n",
				__func__, __LINE__, status);
			vfree(buf);
			return status;
		}
		if (copy_to_user((void *) ((struct ioctlInfo *)arg)->buffer,
			(void *) buf,
			VXGE_REG_DUMP_BUFSIZE)) {
			vfree(buf);
			return -EFAULT;
		}
		vfree(buf);
		goto exit0;
	}
	default:
		return -EOPNOTSUPP;
	}

exit0:

	if (copy_to_user(arg, &ioctl_info, sizeof(ioctl_info)))
		return -EFAULT;

	vxge_debug_entryexit(VXGE_TRACE,
		"%s:%d  Exiting...\n", __func__, __LINE__);
	return 0;

}

/**
 * vxge_tx_watchdog
 * @dev: pointer to net device structure
 *
 * Watchdog for transmit side.
 * This function is triggered if the Tx Queue is stopped
 * for a pre-defined amount of time when the Interface is still up.
 */
static void
vxge_tx_watchdog(struct net_device *dev)
{
	struct vxgedev *vdev;

	vxge_debug_entryexit(VXGE_TRACE, "%s:%d", __func__, __LINE__);

	vdev = (struct vxgedev *)netdev_priv(dev);

	vdev->cric_err_event = VXGE_HW_EVENT_RESET_START;

	schedule_work(&vdev->reset_task);

	vxge_debug_entryexit(VXGE_TRACE,
		"%s:%d  Exiting...", __func__, __LINE__);
}

/**
 * vxge_vlan_rx_register
 * @dev: net device pointer.
 * @grp: vlan group
 *
 * Vlan group registration
 */
static void
vxge_vlan_rx_register(struct net_device *dev, struct vlan_group *grp)
{
	struct vxgedev *vdev;
	struct vxge_vpath *vpath;
	int vp;
	u64 vid;
	enum vxge_hw_status status;
	int i;

	vxge_debug_entryexit(VXGE_TRACE, "%s:%d", __func__, __LINE__);

	vdev = (struct vxgedev *)netdev_priv(dev);
	if (!netif_running(dev)) {
		vdev->vlgrp = grp;
		return;
	}

	vpath = &vdev->vpaths[0];
	if ((NULL == grp) && (vpath->is_open)) {
		/* Get the first vlan */
		status = vxge_hw_vpath_vid_get_vpn(vpath->handle, &vid,
				vpath->handle->vpath->vp_id);

		while (status == VXGE_HW_OK) {

			/* Delete this vlan from the vid table */
			for (vp = 0; vp < vdev->no_of_vpath; vp++) {
				vpath = &vdev->vpaths[vp];
				if (!vpath->is_open)
					continue;

				vxge_hw_vpath_vid_delete_vpn(vpath->handle, vid,
					vpath->handle->vpath->vp_id);
			}

			/* Get the next vlan to be deleted */
			vpath = &vdev->vpaths[0];
			status = vxge_hw_vpath_vid_get_vpn(vpath->handle, &vid,
					vpath->handle->vpath->vp_id);
		}
	}

	vdev->vlgrp = grp;

	for (i = 0; i < vdev->no_of_vpath; i++) {
		if (vdev->vpaths[i].is_configured)
			vdev->vpaths[i].ring.vlgrp = grp;

		if (grp && (vdev->vlan_tag_strip ==
				VXGE_HW_VPATH_RPA_STRIP_VLAN_TAG_ENABLE))
			vdev->vpaths[i].ring.rx_vlan_stripped = TRUE;
		else
			vdev->vpaths[i].ring.rx_vlan_stripped = FALSE;

		vpath = &vdev->vpaths[i];
		if (!vpath->is_open)
			continue;

		vxge_hw_vpath_handle_vlan_tag_strip(
			vdev->devh,
			vdev->vpaths[i].device_id,
			vdev->vpaths[i].ring.rx_vlan_stripped);
	}

	vxge_debug_entryexit(VXGE_TRACE,
		"%s:%d  Exiting...", __func__, __LINE__);
}

/**
 * vxge_vlan_rx_add_vid
 * @dev: net device pointer.
 * @vid: vid
 *
 * Add the vlan id to the devices vlan id table
 */
static void
vxge_vlan_rx_add_vid(struct net_device *dev, unsigned short vid)
{
	struct vxgedev *vdev;
	struct vxge_vpath *vpath;
	int vp_id;

	vdev = (struct vxgedev *)netdev_priv(dev);

	/* Add these vlan to the vid table */
	for (vp_id = 0; vp_id < vdev->no_of_vpath; vp_id++) {
		vpath = &vdev->vpaths[vp_id];
		if (!vpath->is_open)
			continue;
		vxge_hw_vpath_vid_add_vpn(vpath->handle, vid,
			vpath->handle->vpath->vp_id);
	}
}

/**
 * vxge_vlan_rx_add_vid
 * @dev: net device pointer.
 * @vid: vid
 *
 * Remove the vlan id from the device's vlan id table
 */
static void
vxge_vlan_rx_kill_vid(struct net_device *dev, unsigned short vid)
{
	struct vxgedev *vdev;
	struct vxge_vpath *vpath;
	int vp_id;

	vxge_debug_entryexit(VXGE_TRACE, "%s:%d", __func__, __LINE__);

	vdev = (struct vxgedev *)netdev_priv(dev);

	vlan_group_set_device(vdev->vlgrp, vid, NULL);

	/* Delete this vlan from the vid table */
	for (vp_id = 0; vp_id < vdev->no_of_vpath; vp_id++) {
		vpath = &vdev->vpaths[vp_id];
		if (!vpath->is_open)
			continue;
		vxge_hw_vpath_vid_delete_vpn(vpath->handle, vid,
				vpath->handle->vpath->vp_id);
	}
	vxge_debug_entryexit(VXGE_TRACE,
		"%s:%d  Exiting...", __func__, __LINE__);
}

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 28))
static const struct net_device_ops vxge_netdev_ops = {
	.ndo_open               = vxge_open,
	.ndo_stop               = vxge_close,
	.ndo_get_stats          = vxge_get_stats,
	.ndo_start_xmit         = vxge_xmit,
	.ndo_validate_addr      = eth_validate_addr,
	.ndo_set_multicast_list = vxge_set_multicast,
	.ndo_do_ioctl           = vxge_ioctl,
	.ndo_set_mac_address    = vxge_set_mac_addr,
	.ndo_change_mtu         = vxge_change_mtu,
	.ndo_vlan_rx_register   = vxge_vlan_rx_register,
	.ndo_vlan_rx_kill_vid   = vxge_vlan_rx_kill_vid,
	.ndo_vlan_rx_add_vid	= vxge_vlan_rx_add_vid,

	.ndo_tx_timeout         = vxge_tx_watchdog,
#ifdef CONFIG_NET_POLL_CONTROLLER
	.ndo_poll_controller    = vxge_netpoll,
#endif
};
#endif

int __devinit vxge_device_register(struct __vxge_hw_device *hldev,
				   struct vxge_config *config,
				   int high_dma, int no_of_vpath,
				   struct vxgedev **vdev_out)
{
	struct net_device *ndev;
	enum vxge_hw_status status = VXGE_HW_OK;
	struct vxgedev *vdev;
	int ret = 0;
#if defined(VXGE_LLTX)
	int i;
#endif /* LLTX */

	u64 stat;

	*vdev_out = NULL;

	if (config->tx_steering_type)
		ndev = alloc_etherdev_mq(sizeof(struct vxgedev), no_of_vpath);
	else
		ndev = alloc_etherdev_mq(sizeof(struct vxgedev), 1);

	if (ndev == NULL) {
		vxge_debug_init(
			vxge_hw_device_trace_level_get(hldev),
		"%s : device allocation failed", __func__);
		ret = -ENODEV;
		goto _out0;
	}

	vxge_debug_entryexit(
		vxge_hw_device_trace_level_get(hldev),
		"%s: %s:%d  Entering...",
		ndev->name, __func__, __LINE__);

	vdev = netdev_priv(ndev);
	memset(vdev, 0, sizeof(struct vxgedev));

	vdev->ndev = ndev;
	vdev->devh = hldev;
	vdev->pdev = hldev->pdev;
	memcpy(&vdev->config, config, sizeof(struct vxge_config));
	vdev->rx_csum = 1;	/* Enable Rx CSUM by default. */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30))
	vdev->rx_hwts = 0;
#endif
	SET_NETDEV_DEV(ndev, &vdev->pdev->dev);

	ndev->features |= NETIF_F_HW_VLAN_TX | NETIF_F_HW_VLAN_RX |
				NETIF_F_HW_VLAN_FILTER;
	/*  Driver entry points */
	ndev->irq = vdev->pdev->irq;
	ndev->base_addr = (unsigned long) hldev->bar0;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29))
	ndev->open = &vxge_open;
	ndev->stop = &vxge_close;
	ndev->hard_start_xmit = &vxge_xmit;
	ndev->get_stats = &vxge_get_stats;
	ndev->set_multicast_list = &vxge_set_multicast;
	ndev->set_mac_address = &vxge_set_mac_addr;
	ndev->do_ioctl = &vxge_ioctl;
	ndev->change_mtu = &vxge_change_mtu;
#ifdef CONFIG_NET_POLL_CONTROLLER
	ndev->poll_controller = vxge_netpoll;
#endif
	ndev->vlan_rx_register = vxge_vlan_rx_register;
	ndev->vlan_rx_add_vid = vxge_vlan_rx_add_vid;
	ndev->vlan_rx_kill_vid = vxge_vlan_rx_kill_vid;

#ifndef VXGE_HW_TITAN_EMULATION
	ndev->tx_timeout = &vxge_tx_watchdog;
#endif
#else
	ndev->netdev_ops = &vxge_netdev_ops;
#endif

	ndev->watchdog_timeo = VXGE_LL_WATCH_DOG_TIMEOUT;

#if (LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 19))
	INIT_WORK(&vdev->reset_task, (void (*)(void *))vxge_reset, ndev);
#else
	INIT_WORK(&vdev->reset_task, vxge_reset);
#endif
#ifdef SET_ETHTOOL_OPS
	initialize_ethtool_ops(ndev);
#endif

	/* Allocate memory for vpath */
	vdev->vpaths = kzalloc((sizeof(struct vxge_vpath)) *
				no_of_vpath, GFP_KERNEL);
	if (!vdev->vpaths) {
		vxge_debug_init(VXGE_ERR,
			"%s: vpath memory allocation failed",
			vdev->ndev->name);
		ret = -ENODEV;
		goto _out1;
	}

	ndev->features |= NETIF_F_SG;

	ndev->features |= NETIF_F_HW_CSUM;
	vxge_debug_init(vxge_hw_device_trace_level_get(hldev),
		"%s : checksuming enabled", __func__);

	if (high_dma) {
		ndev->features |= NETIF_F_HIGHDMA;
		vxge_debug_init(vxge_hw_device_trace_level_get(hldev),
			"%s : using High DMA", __func__);
	}

#ifdef NETIF_F_RXHASH
	if (config->rx_steering_type != NO_STEERING) {
		ndev->features |= NETIF_F_RXHASH;
		hldev->config.rth_en = VXGE_HW_RTH_ENABLE;
	}
#endif
#ifdef NETIF_F_TSO

	ndev->features |= NETIF_F_TSO;
#ifdef NETIF_F_TSO6
	ndev->features |= NETIF_F_TSO6;
#endif

#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 26))
	vdev->orig_gso_max_sz = ndev->gso_max_size;
#endif

#ifdef NETIF_F_UFO
	if (udp_stream)
		ndev->features |= NETIF_F_UFO;
#endif

	if (vdev->config.lro_enable == VXGE_HW_GRO_ENABLE) {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29))
		ndev->features |= NETIF_F_GRO;
#endif
	}

	if (vdev->config.tx_steering_type == TX_MULTIQ_STEERING)
		vxge_tx_queues_set(ndev, no_of_vpath);

#if defined(VXGE_LLTX)
#ifdef NETIF_F_LLTX
	ndev->features |= NETIF_F_LLTX;
#endif
	for (i = 0; i < no_of_vpath; i++)
		spin_lock_init(&vdev->vpaths[i].fifo.tx_lock);
#endif /* LLTX */

	if (register_netdev(ndev)) {
		vxge_debug_init(vxge_hw_device_trace_level_get(hldev),
			"%s: %s : device registration failed!",
			ndev->name, __func__);
		ret = -ENODEV;
		goto _out2;
	}

	/*  Set the factory defined MAC address initially */
	ndev->addr_len = ETH_ALEN;

	/* Make Link state as off at this point, when the Link change
	 * interrupt comes the state will be automatically changed to
	 * the right state.
	 */
	netif_carrier_off(ndev);

	vxge_debug_init(vxge_hw_device_trace_level_get(hldev),
		"%s: Ethernet device registered",
		ndev->name);

	*vdev_out = vdev;

	/* Resetting the Device stats */
	status = vxge_hw_mrpcim_stats_access(
				hldev,
				VXGE_HW_STATS_OP_CLEAR_ALL_STATS,
				0,
				0,
				&stat);

	if (status == VXGE_HW_ERR_PRIVILAGED_OPEARATION)
		vxge_debug_init(
			vxge_hw_device_trace_level_get(hldev),
			"%s: device stats clear returns"
			"VXGE_HW_ERR_PRIVILAGED_OPEARATION", ndev->name);

	vxge_debug_entryexit(vxge_hw_device_trace_level_get(hldev),
		"%s: %s:%d  Exiting...",
		ndev->name, __func__, __LINE__);

	return ret;
_out2:
	kfree(vdev->vpaths);
_out1:
	free_netdev(ndev);
_out0:
	return ret;
}

/*
 * vxge_device_unregister
 *
 * This function will unregister and free network device
 */
void
vxge_device_unregister(struct __vxge_hw_device *hldev)
{
	struct vxgedev *vdev;
	struct net_device *dev;
	char buf[IFNAMSIZ];
#if ((VXGE_DEBUG_INIT & VXGE_DEBUG_MASK) || \
	(VXGE_DEBUG_ENTRYEXIT & VXGE_DEBUG_MASK))
	u32 level_trace;
#endif

	dev = hldev->ndev;
	vdev = netdev_priv(dev);
#if ((VXGE_DEBUG_INIT & VXGE_DEBUG_MASK) || \
	(VXGE_DEBUG_ENTRYEXIT & VXGE_DEBUG_MASK))
	level_trace = vdev->level_trace;
#endif
	vxge_debug_entryexit(level_trace,
		"%s: %s:%d", vdev->ndev->name, __func__, __LINE__);

	strncpy(buf, vdev->ndev->name, IFNAMSIZ);

	flush_scheduled_work();

	/* in 2.6 will call stop() if device is up */
	unregister_netdev(dev);

	vxge_debug_init(level_trace, "%s: ethernet device unregistered", buf);
	vxge_debug_entryexit(level_trace,
		"%s: %s:%d  Exiting...", buf, __func__, __LINE__);
}

/*
 * vxge_callback_crit_err
 *
 * This function is called by the alarm handler in interrupt context.
 * Driver must analyze it based on the event type.
 */
static void
vxge_callback_crit_err(struct __vxge_hw_device *hldev,
			enum vxge_hw_event type, u64 vp_id)
{
	struct net_device *dev = hldev->ndev;
	struct vxgedev *vdev = (struct vxgedev *)netdev_priv(dev);
	int vpath_idx;

	vxge_debug_entryexit(vdev->level_trace,
		"%s: %s:%d", vdev->ndev->name, __func__, __LINE__);

	/* Note: This event type should be used for device wide
	 * indications only - Serious errors, Slot freeze and critical errors
	 */
	vdev->cric_err_event = type;

	for (vpath_idx = 0; vpath_idx < vdev->no_of_vpath; vpath_idx++)
		if (vdev->vpaths[vpath_idx].device_id == vp_id)
			break;

	if (!test_bit(__VXGE_STATE_RESET_CARD, &vdev->state)) {
		if (type == VXGE_HW_EVENT_SLOT_FREEZE) {
			vxge_debug_init(VXGE_ERR,
				"%s: Slot is frozen", vdev->ndev->name);
		} else if (type == VXGE_HW_EVENT_SERR) {
			vxge_debug_init(VXGE_ERR,
				"%s: Encountered Serious Error",
				vdev->ndev->name);
		} else if (type == VXGE_HW_EVENT_CRITICAL_ERR)
			vxge_debug_init(VXGE_ERR,
				"%s: Encountered Critical Error",
				vdev->ndev->name);
	}

	if ((type == VXGE_HW_EVENT_SERR) ||
		(type == VXGE_HW_EVENT_SLOT_FREEZE)) {
		if (unlikely(vdev->exec_mode))
			clear_bit(__VXGE_STATE_CARD_UP, &vdev->state);
	} else if (type == VXGE_HW_EVENT_CRITICAL_ERR) {
		vxge_hw_device_mask_all(hldev);
		if (unlikely(vdev->exec_mode))
			clear_bit(__VXGE_STATE_CARD_UP, &vdev->state);
	} else if ((type == VXGE_HW_EVENT_FIFO_ERR) ||
		  (type == VXGE_HW_EVENT_VPATH_ERR)) {

		if (unlikely(vdev->exec_mode))
			clear_bit(__VXGE_STATE_CARD_UP, &vdev->state);
		else {
			/* check if this vpath is already set for reset */
			if (!test_and_set_bit(vpath_idx, &vdev->vp_reset)) {

				/* disable interrupts for this vpath */
				vxge_vpath_intr_disable(vdev, vpath_idx);

				/* stop the queue for this vpath */
				vxge_stop_tx_queue(&vdev->vpaths[vpath_idx].
							fifo);
			}
		}
	}

	vxge_debug_entryexit(vdev->level_trace,
		"%s: %s:%d  Exiting...",
		vdev->ndev->name, __func__, __LINE__);
}

/*
 * Vpath configuration
 */
static int __devinit vxge_config_vpaths(
			struct vxge_hw_device_config *device_config,
			u64 vpath_mask, struct vxge_config *config_param)
{
	int i, no_of_vpaths = 0, default_no_vpath = 0, temp;
	u32 txdl_size, txdl_per_memblock;
	int no_online_cpus = 0;

	temp = driver_config->vpath_per_dev;
	if ((driver_config->vpath_per_dev == VXGE_USE_DEFAULT)) {

		{

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 67))
		for (i = 0; i < NR_CPUS; i++) {
			if (cpu_online_map & (1<<i))
				no_online_cpus++;
		}
#else
		no_online_cpus = num_online_cpus();
#endif
		vxge_assert(no_online_cpus > 0);

		driver_config->vpath_per_dev = no_online_cpus >> 1;
		if (!driver_config->vpath_per_dev)
			driver_config->vpath_per_dev = 1;

		for (i = 0; i < VXGE_HW_MAX_VIRTUAL_PATHS; i++)
			if (!vxge_bVALn(vpath_mask, i, 1))
				continue;
			else
				default_no_vpath++;
		if (default_no_vpath < driver_config->vpath_per_dev)
			driver_config->vpath_per_dev = default_no_vpath;

#ifdef ESX_KL
		/*
		 * To use multiple FIFOs both netq and tx_steering should
		 * be enabled.
		 */
		if ((!config_param->tx_steering_type) || (!netq)) {
			config_param->tx_steering_type = NO_STEERING;
			netq = 0;
		}
#endif
		/* If both tx_steering and Rx_steering are
		   disabled, enable only one Vpath */
		if ((!config_param->tx_steering_type &&
			(config_param->rx_steering_type == NO_STEERING)

			)) {
			driver_config->vpath_per_dev = 1;
			vxge_debug_ll_config(VXGE_TRACE,
				"%s: Configuring single vpath,\
				as transmit and receive \
				steering is disabled",
				VXGE_DRIVER_NAME);
		}

		}
	}
	for (i = 0; i < VXGE_HW_MAX_VIRTUAL_PATHS; i++) {
		device_config->vp_config[i].vp_id = i;
		device_config->vp_config[i].mtu = VXGE_HW_DEFAULT_MTU;
		if (no_of_vpaths < driver_config->vpath_per_dev) {
			if (!vxge_bVALn(vpath_mask, i, 1)) {
				vxge_debug_ll_config(VXGE_TRACE,
					"%s: vpath: %d is not available",
					VXGE_DRIVER_NAME, i);
				continue;
			} else {
				vxge_debug_ll_config(VXGE_TRACE,
					"%s: vpath: %d available",
					VXGE_DRIVER_NAME, i);
				no_of_vpaths++;
			}
		} else {
			vxge_debug_ll_config(VXGE_TRACE,
				"%s: vpath: %d is not configured, "
				"max_config_vpath exceeded",
				VXGE_DRIVER_NAME, i);
			break;
		}

		/* Configure Tx fifo's */
		device_config->vp_config[i].fifo.enable =
					VXGE_HW_FIFO_ENABLE;

		device_config->vp_config[i].fifo.max_frags =
				MAX_SKB_FRAGS + 1;
		device_config->vp_config[i].fifo.memblock_size =
			VXGE_HW_MIN_FIFO_MEMBLOCK_SIZE;

		txdl_size = device_config->vp_config[i].fifo.max_frags *
			sizeof(struct vxge_hw_fifo_txd);
		txdl_per_memblock = VXGE_HW_MIN_FIFO_MEMBLOCK_SIZE / txdl_size;

		device_config->vp_config[i].fifo.fifo_blocks =
			((VXGE_DEF_FIFO_LENGTH - 1) / txdl_per_memblock) + 1;

		device_config->vp_config[i].fifo.intr =
				VXGE_HW_FIFO_QUEUE_INTR_DISABLE;

		/* Configure tti properties */
		device_config->vp_config[i].tti.intr_enable =
					VXGE_HW_TIM_INTR_ENABLE;

		device_config->vp_config[i].tti.btimer_val =
			(VXGE_TTI_BTIMER_VAL * 1000) / 272;

		device_config->vp_config[i].tti.timer_ac_en =
				VXGE_HW_TIM_TIMER_AC_ENABLE;

		if (config_param->intr_type == MSI_X) {
			device_config->vp_config[i].rti.btimer_val =
			    ((VXGE_RTI_BTIMER_VAL * 1000)/272);
		} else {
			device_config->vp_config[i].rti.btimer_val =
				((VXGE_RTI_BTIMER_DEFAULT_VAL * 1000)/272);
		}

		/*
		 * Enable CI for RTI after interrupts are enabled in
		 * in vxge_open. Otherwise, occasionally, when NAPI is
		 * enabled, the rx interrupt does not fire when
		 * the driver loads on system boot.
		 */
		device_config->vp_config[i].rti.timer_ci_en =
			VXGE_HW_TIM_TIMER_CI_DISABLE;

		device_config->vp_config[i].tti.timer_ci_en =
			VXGE_HW_TIM_TIMER_CI_DISABLE;

		device_config->vp_config[i].tti.timer_ri_en =
				VXGE_HW_TIM_TIMER_RI_DISABLE;

		device_config->vp_config[i].tti.util_sel =
			VXGE_HW_TIM_UTIL_SEL_LEGACY_TX_NET_UTIL;

		device_config->vp_config[i].tti.ltimer_val =
			(VXGE_TTI_LTIMER_VAL * 1000) / 272;

		device_config->vp_config[i].tti.rtimer_val =
			(VXGE_TTI_RTIMER_VAL * 1000) / 272;

		device_config->vp_config[i].tti.urange_a = TTI_TX_URANGE_A;
		device_config->vp_config[i].tti.urange_b = TTI_TX_URANGE_B;
		device_config->vp_config[i].tti.urange_c = TTI_TX_URANGE_C;
		device_config->vp_config[i].tti.uec_a = TTI_TX_UFC_A;
		device_config->vp_config[i].tti.uec_b = TTI_TX_UFC_B;
		device_config->vp_config[i].tti.uec_c = TTI_TX_UFC_C;
		device_config->vp_config[i].tti.uec_d = TTI_TX_UFC_D;

		/* Configure Rx rings */
		device_config->vp_config[i].ring.enable  =
						VXGE_HW_RING_ENABLE;

		device_config->vp_config[i].ring.ring_blocks  =
						VXGE_HW_DEF_RING_BLOCKS;
		device_config->vp_config[i].ring.buffer_mode =
			VXGE_HW_RING_RXD_BUFFER_MODE_1;

		if ((device_config->lro_enable) &&
			(device_config->lro_enable != VXGE_HW_GRO_ENABLE)) {
		    device_config->vp_config[i].ring.sw_lro_sessions =
					    VXGE_HW_SW_LRO_DEFAULT_SESSIONS;
		    device_config->vp_config[i].ring.sw_lro_sg_size =
					    VXGE_HW_SW_LRO_MAX_SG_SIZE;
		    device_config->vp_config[i].ring.sw_lro_frm_len =
					    VXGE_HW_SW_LRO_MAX_FRM_LEN;
		}

		device_config->vp_config[i].ring.rxd_qword_limit =
				VXGE_HW_DEF_RING_RXD_QWORD_LIMIT;

		device_config->vp_config[i].ring.scatter_mode =
					VXGE_HW_RING_SCATTER_MODE_A;

		/* Configure rti properties */
		device_config->vp_config[i].rti.intr_enable =
					VXGE_HW_TIM_INTR_ENABLE;

		device_config->vp_config[i].rti.timer_ac_en =
						VXGE_HW_TIM_TIMER_AC_ENABLE;

		device_config->vp_config[i].rti.timer_ri_en =
						VXGE_HW_TIM_TIMER_RI_DISABLE;

		device_config->vp_config[i].rti.util_sel =
				VXGE_HW_TIM_UTIL_SEL_LEGACY_RX_NET_UTIL;

		device_config->vp_config[i].rti.urange_a =
						RTI_RX_URANGE_A;
		device_config->vp_config[i].rti.urange_b =
						RTI_RX_URANGE_B;
		device_config->vp_config[i].rti.urange_c =
						RTI_RX_URANGE_C;
		device_config->vp_config[i].rti.uec_a = RTI_RX_UFC_A;
		device_config->vp_config[i].rti.uec_b = RTI_RX_UFC_B;
		device_config->vp_config[i].rti.uec_c = RTI_RX_UFC_C;
		device_config->vp_config[i].rti.uec_d = RTI_RX_UFC_D;

		device_config->vp_config[i].rti.rtimer_val =
			(VXGE_RTI_RTIMER_VAL * 1000) / 272;

		device_config->vp_config[i].rti.ltimer_val =
			(VXGE_RTI_LTIMER_VAL * 1000) / 272;

		device_config->vp_config[i].rpa_strip_vlan_tag =
			vlan_tag_strip;
	}

	driver_config->vpath_per_dev = temp;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24))
	/* NAPI doesn't work well with MSI(X) & more than 1 VPATH */
	if (config_param->intr_type != INTA)
		if (config_param->napi_enable)
			if (no_of_vpaths > 1)
				config_param->napi_enable = 0;
#endif

	return no_of_vpaths;
}

/* initialize device configuratrions */
static void __devinit vxge_device_config_init(
				struct vxge_hw_device_config *device_config,
				int *intr_type)
{
	device_config->stats_read_method = VXGE_HW_STATS_READ_METHOD_PIO;

	if ((max_rx_buffer_size > VXGE_HW_MAX_MTU) ||
		(max_rx_buffer_size < VXGE_HW_MIN_MTU)) {
		max_rx_buffer_size = VXGE_HW_DEFAULT_MTU;
		vxge_debug_init(VXGE_ERR,
			"%s: Invalid value for max_rx_buffer_size,"
			"Defaulting to %d \n", VXGE_DRIVER_NAME,
			VXGE_HW_DEFAULT_MTU);
	}
	if (max_mac_vpath > VXGE_MAX_MAC_ADDR_COUNT) {
		max_mac_vpath = VXGE_MAX_MAC_ADDR_COUNT;
		vxge_debug_init(VXGE_ERR,
			"%s: Invalid setting for vpath mac address limit. "
			"Defaulting to %d", VXGE_DRIVER_NAME, max_mac_vpath);
	} else if (max_mac_vpath < VXGE_DEF_MAC_ADDR_COUNT) {
		max_mac_vpath = VXGE_DEF_MAC_ADDR_COUNT;
		vxge_debug_init(VXGE_ERR,
			"%s: Invalid setting for vpath mac address limit. "
			"Defaulting to %d", VXGE_DRIVER_NAME, max_mac_vpath);
	}

#ifndef CONFIG_PCI_MSI
	if (*intr_type == MSI_X) {
		vxge_debug_init(VXGE_ERR,
			"%s: This Kernel does not support "
			"MSI-X. Defaulting to INTA", VXGE_DRIVER_NAME);
		*intr_type = INTA;
	}
#endif

	/* Configure whether MSI-X or IRQL. */
	switch (*intr_type) {
	case INTA:
		device_config->intr_mode = VXGE_HW_INTR_MODE_IRQLINE;
		break;

	case MSI_X:
		device_config->intr_mode = VXGE_HW_INTR_MODE_MSIX_ONE_SHOT;
		break;
	}

	device_config->lro_enable = lro;
	/* Timer period between device poll */
	device_config->device_poll_millis = VXGE_TIMER_DELAY;

	/* Configure Vpaths */
	device_config->rth_it_type = VXGE_HW_RTH_IT_TYPE_MULTI_IT;

	vxge_debug_ll_config(VXGE_TRACE, "%s : Device Config Params ",
			__func__);
	vxge_debug_ll_config(VXGE_TRACE, "intr_mode : %d",
			device_config->intr_mode);
	vxge_debug_ll_config(VXGE_TRACE, "device_poll_millis : %d",
			device_config->device_poll_millis);
	vxge_debug_ll_config(VXGE_TRACE, "rth_en : %d",
			device_config->rth_en);
	vxge_debug_ll_config(VXGE_TRACE, "rth_it_type : %d",
			device_config->rth_it_type);
}

static void __devinit vxge_print_parm(struct vxgedev *vdev, u64 vpath_mask)
{
	int i, ports;
	enum vxge_hw_status status = VXGE_HW_OK;
	u64 active_config = 0;

	vxge_debug_init(VXGE_TRACE,
		"%s: %d Vpath(s) opened",
		vdev->ndev->name, vdev->no_of_vpath);

	switch (vdev->config.intr_type) {
	case INTA:
		vxge_debug_init(VXGE_TRACE,
			"%s: Interrupt type INTA", vdev->ndev->name);
		break;

	case MSI_X:
		vxge_debug_init(VXGE_TRACE,
			"%s: Interrupt type MSI-X", vdev->ndev->name);
		break;

	}

	switch (vdev->config.rx_steering_type) {
	case RTH_TCP_UDP_STEERING:
		vxge_debug_init(VXGE_TRACE,
			"%s: RTH steering enabled for TCP_IPV4",
			vdev->ndev->name);
		break;
	case RTH_IPV4_STEERING:
		vxge_debug_init(VXGE_TRACE,
			"%s: RTH steering enabled for IPV4",
			vdev->ndev->name);
		break;
	case RTH_IPV6_EX_STEERING:
		vxge_debug_init(VXGE_TRACE,
			"%s: RTH steering enabled for IPV6 with extention header",
			vdev->ndev->name);
		break;
	default:
		vxge_debug_init(VXGE_TRACE,
			"%s: RTH steering disabled", vdev->ndev->name);
	}

	if (vdev->config.lro_enable == VXGE_HW_GRO_ENABLE) {
		vxge_debug_init(VXGE_ERR,
			"%s: Generic receive offload enabled",
			vdev->ndev->name);
	} else if (vdev->config.lro_enable) {
		vxge_debug_init(VXGE_TRACE,
			"%s: Large receive offload enabled",
			vdev->ndev->name);
	} else
		vxge_debug_init(VXGE_TRACE,
			"%s: Large receive offload disabled",
			vdev->ndev->name);

	switch (vdev->config.tx_steering_type) {
	case NO_STEERING:
		vxge_debug_init(VXGE_TRACE,
			"%s: Tx steering disabled", vdev->ndev->name);
		break;
	case TX_PRIORITY_STEERING:
		vxge_debug_init(VXGE_TRACE,
			"%s: Unsupported tx steering option",
			vdev->ndev->name);
		vxge_debug_init(VXGE_TRACE,
			"%s: Tx steering disabled", vdev->ndev->name);
		vdev->config.tx_steering_type = 0;
		break;
	case TX_VLAN_STEERING:
		vxge_debug_init(VXGE_TRACE,
			"%s: Unsupported tx steering option",
			vdev->ndev->name);
		vxge_debug_init(VXGE_TRACE,
			"%s: Tx steering disabled", vdev->ndev->name);
		vdev->config.tx_steering_type = 0;
		break;
	case TX_MULTIQ_STEERING:
		vxge_debug_init(VXGE_TRACE,
			"%s: Tx multiqueue steering enabled",
			vdev->ndev->name);
		break;
	case TX_PORT_STEERING:
		vxge_debug_init(VXGE_TRACE,
			"%s: Tx port steering enabled",
			vdev->ndev->name);
		break;
	default:
		vxge_debug_init(VXGE_ERR,
			"%s: Unsupported tx steering type",
			vdev->ndev->name);
		vxge_debug_init(VXGE_TRACE,
			"%s: Tx steering disabled", vdev->ndev->name);
		vdev->config.tx_steering_type = 0;
	}

	if (vdev->config.napi_enable) {
		vxge_debug_init(VXGE_TRACE,
				"%s: NAPI enabled", vdev->ndev->name);
	} else
		vxge_debug_init(VXGE_TRACE,
				"%s: NAPI disabled", vdev->ndev->name);

	if (vdev->config.promisc_en)
		vxge_debug_init(VXGE_TRACE,
			"%s: Promiscuous mode enabled on privileged function",
			vdev->ndev->name);

	if (vdev->config.promisc_all_en)
		vxge_debug_init(VXGE_TRACE,
			"%s: Promiscuous mode enabled on all functions",
			vdev->ndev->name);

	if (vdev->config.ack_aggr)
			vxge_debug_init(VXGE_TRACE,
			"%s: Ack aggregation enabled", vdev->ndev->name);

	if (vdev->exec_mode == VXGE_EXEC_MODE_ENABLE)
		vxge_debug_init (VXGE_ERR, "%s: Exec debug mode enabled",
					vdev->ndev->name);

	if (!vdev->titan1)
		if (intr_adapt)
			vxge_debug_init (VXGE_ERR, "%s: Adaptive interrupt "
			"coalescing enabled", vdev->ndev->name);

	for (i = 0; i < VXGE_HW_MAX_VIRTUAL_PATHS; i++) {
		if (!vxge_bVALn(vpath_mask, i, 1))
			continue;
		vxge_debug_ll_config(VXGE_TRACE,
			"%s: MTU size - %d", vdev->ndev->name,
			((struct __vxge_hw_device  *)(vdev->devh))->
				config.vp_config[i].mtu);
		vxge_debug_init(VXGE_TRACE,
			"%s: VLAN tag stripping %s", vdev->ndev->name,
			((struct __vxge_hw_device  *)(vdev->devh))->
				config.vp_config[i].rpa_strip_vlan_tag
			? "enabled" : "disabled");
		vxge_debug_ll_config(VXGE_TRACE,
			"%s: Max frags : %d", vdev->ndev->name,
			((struct __vxge_hw_device  *)(vdev->devh))->
				config.vp_config[i].fifo.max_frags);
		break;
	}

	status = __vxge_hw_device_is_privilaged(vdev->devh->host_type,
			vdev->devh->func_id);
	if (status == VXGE_HW_OK) {
		status = vxge_hw_get_active_config(vdev->devh,
				VXGE_HW_XMAC_NWIF_ActConfig_NWPortMode,
				&active_config);
		if (status == VXGE_HW_OK)
			vxge_debug_init(VXGE_TRACE,
				"%s: Port mode: %s",
				vdev->ndev->name,
				vxge_port_mode_names[active_config]);

		/* Display port_behavior only if adapter has 2 physical ports */
		status = __vxge_hw_get_port_cnt(vdev->devh, &ports);
		if ((status == VXGE_HW_OK) && (ports == 2) &&
			(active_config != VXGE_HW_DP_NP_MODE_SINGLE_PORT)) {
			status = vxge_hw_get_active_config(vdev->devh,
				  VXGE_HW_XMAC_NWIF_ActConfig_BehaviourOnFail,
				  &active_config);
			if (status == VXGE_HW_OK)
				vxge_debug_init(VXGE_TRACE,
				  "%s: Port behavior: %s",
				  vdev->ndev->name,
				  vxge_port_behavior_names[active_config]);
		}

		status = vxge_hw_get_active_config(vdev->devh,
				  VXGE_HW_XMAC_NWIF_ActConfig_L2SwitchEnabled,
				  &active_config);
			if (status == VXGE_HW_OK)
				vxge_debug_init(VXGE_TRACE,
					"%s: L2 Switch: %s",
					vdev->ndev->name,
					active_config ? "Enabled" : "Disabled");
	}

#ifdef VXGE_PF_RING
	vxge_debug_init(VXGE_TRACE, "PF_RING support %s",
			pf_ring_en ? "enabled" : "disabled");

	if(pf_ring_en) {	  
	  vxge_debug_init(VXGE_TRACE, "PF_RING debugging %s",
			  pf_ring_debug ? "enabled" : "disabled");
	}

	vxge_debug_init(VXGE_TRACE, "RX hardware timestamps %s", 	 
			vdev->rx_hwts ? "enabled" : "disabled");
#endif
}

#ifdef CONFIG_PM
/**
 * vxge_pm_suspend - vxge power management suspend entry point
 *
 */
static int vxge_pm_suspend(struct pci_dev *pdev, pm_message_t state)
{
	int ret = 0;
	struct __vxge_hw_device  *hldev =
		(struct __vxge_hw_device  *) pci_get_drvdata(pdev);
	struct net_device *netdev = hldev->ndev;

	pci_save_state(pdev);
	if (netif_running(netdev)) {
		do_vxge_close(netdev, 1);
		netif_device_detach(netdev);
	}
	ret = pci_set_power_state(pdev, pci_choose_state(pdev, state));
	if (ret)
		vxge_debug_init(VXGE_ERR,
			"%s: Error %d setting power state\n",
			netdev->name, ret);
	pci_disable_device(pdev);
	return ret;
}
/**
 * vxge_pm_resume - vxge power management resume entry point
 *
 */
static int vxge_pm_resume(struct pci_dev *pdev)
{
	int ret = 0;
	struct __vxge_hw_device  *hldev =
		(struct __vxge_hw_device  *) pci_get_drvdata(pdev);
	struct net_device *netdev = hldev->ndev;

	ret = pci_set_power_state(pdev, PCI_D0);
	if (ret) {
		vxge_debug_init(VXGE_ERR,
			"%s: Error %d setting power state\n",
			netdev->name, ret);
		return ret;
	}
	ret = pci_enable_device(pdev);
	pci_set_master(pdev);
	pci_restore_state(pdev);
	if (netif_running(netdev)) {
		ret = vxge_open(netdev);
		if (ret)
			vxge_debug_init(VXGE_ERR,
				"%s: H/W Init failed with err : %d\n",
				netdev->name, ret);
	}
	netif_device_attach(netdev);

	return ret;
}

#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 21))
/**
 * vxge_io_error_detected - called when PCI error is detected
 * @pdev: Pointer to PCI device
 * @state: The current pci connection state
 *
 * This function is called after a PCI bus error affecting
 * this device has been detected.
 */
static pci_ers_result_t vxge_io_error_detected(struct pci_dev *pdev,
						pci_channel_state_t state)
{
	struct __vxge_hw_device  *hldev =
		(struct __vxge_hw_device  *) pci_get_drvdata(pdev);
	struct net_device *netdev = hldev->ndev;

	netif_device_detach(netdev);

	if (state == pci_channel_io_perm_failure)
		return PCI_ERS_RESULT_DISCONNECT;

	if (netif_running(netdev)) {
		/* Bring down the card, while avoiding PCI I/O */
		do_vxge_close(netdev, 0);
	}

	pci_disable_device(pdev);

	return PCI_ERS_RESULT_NEED_RESET;
}

/**
 * vxge_io_slot_reset - called after the pci bus has been reset.
 * @pdev: Pointer to PCI device
 *
 * Restart the card from scratch, as if from a cold-boot.
 * At this point, the card has exprienced a hard reset,
 * followed by fixups by BIOS, and has its config space
 * set up identically to what it was at cold boot.
 */
static pci_ers_result_t vxge_io_slot_reset(struct pci_dev *pdev)
{
	struct __vxge_hw_device  *hldev =
		(struct __vxge_hw_device  *) pci_get_drvdata(pdev);
	struct net_device *netdev = hldev->ndev;

	struct vxgedev *vdev = netdev_priv(netdev);

	if (pci_enable_device(pdev)) {
		printk(KERN_ERR "%s: "
			"Cannot re-enable device after reset\n",
			VXGE_DRIVER_NAME);
		return PCI_ERS_RESULT_DISCONNECT;
	}

	pci_set_master(pdev);
	do_vxge_reset(vdev, VXGE_LL_FULL_RESET);

	return PCI_ERS_RESULT_RECOVERED;
}

/**
 * vxge_io_resume - called when traffic can start flowing again.
 * @pdev: Pointer to PCI device
 *
 * This callback is called when the error recovery driver tells
 * us that its OK to resume normal operation.
 */
static void vxge_io_resume(struct pci_dev *pdev)
{
	struct __vxge_hw_device  *hldev =
		(struct __vxge_hw_device  *) pci_get_drvdata(pdev);
	struct net_device *netdev = hldev->ndev;

	if (netif_running(netdev)) {
		if (vxge_open(netdev)) {
			printk(KERN_ERR "%s: "
				"Can't bring device back up after reset\n",
				VXGE_DRIVER_NAME);
			return;
		}
	}

	netif_device_attach(netdev);
}
#endif

#ifdef VXGE_SNMP
/*
 * vxge_get_mibbase_info :
 * @vdev: referecne to vxge private structure
 * @dev: refernce to the mib base structure
 * Return: void
 * Description: it fills general base driver  objects
 * to the mib base structure
 */
static void vxge_get_mibbase_info(struct mib_base *base)
{
	memset(base, 0, sizeof(*base));

	memcpy(base->name, VXGE_DRIVER_NAME, 32);
	memcpy(base->version, DRV_VERSION, 32);
	strcpy(base->build_date, __DATE__);
	strcpy(base->speed, "10 Gbps");
	base->intr_type       = intr_type;
	base->doorbell        = 1;
	base->lro             = lro;
	base->lro_aggr_packet = (VXGE_T1A_LRO_MAX_BYTES - 1)
				/ VXGE_HW_DEFAULT_MTU;
	base->napi            = napi;
	base->vlan_tag_strip  = vlan_tag_strip;
	base->rx_steering     = rx_steering_type;
	base->tx_steering     = tx_steering_type;
}

/*
 * vxge_proc_base_read : proc read entry point for
 * /proc/net/vxge/base
 * @page: buffer pointer where mib objects are written
 * @start: we do not use it as we use a single page
 * @off: offset to the page where data is written
 * @count: number of bytes to write
 * @eof: indicate end of file
 * @data: reference to vxge private structure
 * Return: length of data written to the page
 * Description: it collects the mib objects of base driver
 * and will write to the proc table.
 */
static int vxge_proc_base_read(char *page, char **start,
		off_t off, int count, int *eof, void *data)
{
	struct mib_base *base;
	int len = 0;

	base = kmalloc(sizeof(struct mib_base), GFP_KERNEL);
	if (!base) {
		vxge_debug_init(VXGE_ERR,
				"%s: out of memory\n", __func__);
		return -ENOMEM;
	}
	vxge_get_mibbase_info(base);
	len += sprintf(page + len, "%-30s: %-20s\n",
			"Driver name", base->name);
	len += sprintf(page + len, "%-30s: %-20s\n",
			"Driver version", base->version);
	len += sprintf(page + len, "%-30s: %-20s\n",
			"Build Date", base->build_date);
	len += sprintf(page + len, "%-30s: %-20s\n",
			"Device speed", base->speed);
	len += sprintf(page + len, "%-30s: %-20d\n",
			"Interrupt type", base->intr_type);
	len += sprintf(page + len, "%-30s: %-20d\n",
			"Doorbell mode", base->doorbell);
	len += sprintf(page + len, "%-30s: %-20d\n",
			"LRO", base->lro);
	len += sprintf(page + len, "%-30s: %-20d\n",
			"LRO aggregate packet", base->lro_aggr_packet);
	len += sprintf(page + len, "%-30s: %-20d\n",
			"NAPI", base->napi);
	len += sprintf(page + len, "%-30s: %-20d\n",
			"VLAN tag strip", base->vlan_tag_strip);
	len += sprintf(page + len, "%-30s: %-20d\n",
			"RX steering type", base->rx_steering);
	len += sprintf(page + len, "%-30s: %-20d\n",
			"TX steering type", base->tx_steering);
	kfree(base);
	*eof = 1;
	return len;
}

/*
 * vxge_get_mibdev_info :
 * @pdev: referecne to pci dev structure
 * @dev: refernce to the mib device structure
 * Return: 0 if success, errno on failure
 * Description: it fills all device specific objects
 * to the mib device structure
 */
static int vxge_get_mibdev_info(struct pci_dev *pdev,
		struct mib_dev *dev)
{
	struct __vxge_hw_device *hldev;
	struct net_device *netdev;
	struct vxgedev *vdev;
	struct net_device_stats *nstat;
	u8 *addr;

	if ((pdev->vendor != PCI_VENDOR_ID_S2IO) ||
		((pdev->device != PCI_DEVICE_ID_TITAN_UNI) &&
		(pdev->device != PCI_DEVICE_ID_TITAN_WIN)))
		return -EPERM;

	hldev = (struct __vxge_hw_device *)pci_get_drvdata(pdev);
	if (!hldev)
		return -EPERM;
	netdev = hldev->ndev;
	if (!netdev || !netdev->addr_len)
		return -EPERM;

	vdev = netdev_priv(netdev);
	memcpy(dev->name, netdev->name, 32);
	dev->index = netdev->ifindex;
	sprintf(dev->bdf, "%02x:%02x.%x", pdev->bus->number,
		PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn));
	dev->vendor_id = pdev->vendor;
	dev->device_id = pdev->device;
	dev->irq       = pdev->irq;
	dev->func_mode = vdev->config.device_hw_info.function_mode;
	dev->access    = (__vxge_hw_device_is_privilaged(hldev->host_type,
				hldev->func_id) == VXGE_HW_OK);
	dev->bandwidth     = 100; /*TODO*/
	dev->vpath_count   = vdev->no_of_vpath;
	dev->link_mode     = 0; /*TODO*/
	dev->active_link   = 1; /*TODO*/
	addr               = vdev->vpaths[0].macaddr;
	sprintf(dev->perm_hw_addr, "%02x:%02x:%02x:%02x:%02x:%02x",
		addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
	dev->tx_intr_count = 0; /*TODO*/
	dev->rx_intr_count = 0; /*TODO*/
	/*netdev*/
	addr            = netdev->dev_addr;
	sprintf(dev->curr_hw_addr, "%02x:%02x:%02x:%02x:%02x:%02x",
		addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
	dev->mtu        = netdev->mtu;
	dev->link_state = netif_carrier_ok(netdev);
	dev->rx_csum    = vdev->rx_csum;
	dev->tx_csum    = (netdev->features & NETIF_F_HW_CSUM) ? 1 : 0;
	dev->tso        = 0;
#ifdef NETIF_F_TSO
	dev->tso        = (netdev->features & NETIF_F_TSO) ? 1 : 0;
#endif
	dev->ufo        = 0;
#ifdef NETIF_F_UFO
	if (udp_stream)
		dev->ufo = (netdev->features & NETIF_F_UFO) ? 1 : 0;
	else
		dev->ufo = 0;
#endif
	dev->sg         = (netdev->features & NETIF_F_SG) ? 1 : 0;
	/* netdev stat*/
	nstat = vxge_get_stats (netdev);
	dev->collision  = nstat->collisions;
	dev->multicast  = nstat->multicast;
	dev->rx_bytes   = nstat->rx_bytes;
	dev->rx_packets = nstat->rx_packets;
	dev->rx_dropped = nstat->rx_dropped;
	dev->rx_errors  = nstat->rx_errors;
	dev->tx_bytes   = nstat->tx_bytes;
	dev->tx_packets = nstat->tx_packets;
	dev->tx_dropped = nstat->tx_dropped;
	dev->tx_errors  = nstat->tx_errors;
	return 0;
}

/*
 * vxge_proc_dev_table_read : proc read entry point for
 * /proc/net/vxge/dev_table
 * @page: buffer pointer where mib objects are written
 * @start: we do not use it as we use a single page
 * @off: offset to the page where data is written
 * @count: number of bytes to write
 * @eof: indicate end of file
 * @data: reference to vxge private structure
 * Return: length of data written to the page
 * Description: it collects the mib objects of all vxge device
 * attached and write to the proc table.
 */
static int vxge_proc_dev_table_read(char *page, char **start,
		off_t off, int count, int *eof, void *data)
{
	struct mib_dev *dev;
	struct pci_dev *pdev = NULL;
	int len, row_width;

	dev = kmalloc(sizeof(struct mib_dev), GFP_KERNEL);
	if (!dev) {
		vxge_debug_init(VXGE_ERR,
			"%s: out of memory\n", __func__);
		return -ENOMEM;
	}
	/* preparing header */
	len = sprintf(page, "%-6s%-6s%-10s%-10s%-10s",
		"id", "name", "bdf", "vendor", "device");
	len += sprintf(page + len, "%-6s%-6s%-8s%-6s%-6s",
		"irq", "func", "access", "bw", "vpath");
	len += sprintf(page + len, "%-10s%-10s%-20s%-20s",
		"link_mode", "act_link", "perm_addr", "curr_addr");
	len += sprintf(page + len, "%-12s%-6s%-10s%-10s",
		"link_state", "mtu", "rxcsum", "txcsum");
	len += sprintf(page + len, "%-6s%-6s%-6s%-12s%-12s",
		"tso", "ufo", "sg", "tx_intr", "rx_intr");
	len += sprintf(page + len, "%-12s%-12s%-12s",
		"collision", "multicast", "rx_bytes");
	len += sprintf(page + len, "%-12s%-12s%-12s",
		"rx_packets", "rx_dropped", "rx_errors");
	len += sprintf(page + len, "%-12s%-12s%-12s%-12s\n",
		"tx_bytes", "tx_packets", "tx_dropped", "tx_errors");
	row_width = len;

	while ((pdev = vxge_pci_find_device(PCI_ANY_ID, PCI_ANY_ID, pdev))
			!= NULL) {
		/* give up, if no space left for another row */
		if ((PAGE_SIZE - len) < row_width)
			break;
		if (vxge_get_mibdev_info(pdev, dev))
			continue;
		len += sprintf(page + len, "%-6u%-6s%-10s",
			dev->index, dev->name, dev->bdf);
		len += sprintf(page + len, "%-10u%-10u%-6u",
			dev->vendor_id, dev->device_id, dev->irq);
		len += sprintf(page + len, "%-6u%-8u%-6u",
			dev->func_mode, dev->access, dev->bandwidth);
		len += sprintf(page + len, "%-6u%-10u%-10u",
			dev->vpath_count, dev->link_mode, dev->active_link);
		len += sprintf(page + len, "%-20s%-20s%-12u",
			dev->perm_hw_addr, dev->curr_hw_addr, dev->link_state);
		len += sprintf(page + len, "%-6u%-10u%-10u",
			dev->mtu, dev->rx_csum, dev->tx_csum);
		len += sprintf(page + len, "%-6u%-6u%-6u",
			dev->tso, dev->ufo, dev->sg);
		len += sprintf(page + len, "%-12llu%-12llu%-12llu",
			dev->tx_intr_count, dev->rx_intr_count, dev->collision);
		len += sprintf(page + len, "%-12llu%-12llu%-12llu",
			dev->multicast, dev->rx_bytes, dev->rx_packets);
		len += sprintf(page + len, "%-12llu%-12llu%-12llu",
			dev->rx_dropped, dev->rx_errors, dev->tx_bytes);
		len += sprintf(page + len, "%-12llu%-12llu%-12llu\n",
			dev->tx_packets, dev->tx_dropped, dev->tx_errors);
	}
	kfree(dev);
	*eof = 1;
	return len;
}

/*
 * vxge_snmp_init : initialize the proc entry for mib objects
 * @vdev : reference to vxge private structure
 * return : 0 if success, errno on failure
 * Description : the function will be called when device is probed.
 * It will create the proc entry for base driver and device table
 * in /proc/net/vxge/ directory.
 */
static int vxge_snmp_init(void)
{
	struct proc_dir_entry *mib, *base, *dev;

	/* Check if mib proc directory already exists */
	mib = vxge_proc_entry_check(proc_net, VXGE_PROC_MIB_DIR);
	if (!mib) {
		mib = create_proc_entry(VXGE_PROC_MIB_DIR,
				S_IFDIR, proc_net);
		if (!mib) {
			vxge_debug_init(VXGE_ERR,
					"%s: mib proc dir creation"
					" failed\n", __func__);
			return -EPERM;
		}
	}

	base = vxge_proc_entry_check(mib, VXGE_PROC_BASE_FILE);
	if (!base) {
		base = create_proc_read_entry(VXGE_PROC_BASE_FILE,
				S_IFREG | S_IRUSR, mib,
				vxge_proc_base_read, NULL);
		if (!base) {
			vxge_debug_init(VXGE_ERR,
					"%s: base proc file creation"
					" failed\n", __func__);
			return -EPERM;
		}
	}

	dev = vxge_proc_entry_check(mib, VXGE_PROC_DEV_FILE);
	if (!dev) {
		dev = create_proc_read_entry(VXGE_PROC_DEV_FILE,
				S_IFREG | S_IRUSR, mib,
				vxge_proc_dev_table_read, NULL);
		if (!dev) {
			vxge_debug_init(VXGE_ERR,
					"%s: dev_table proc file creation"
					" failed\n", __func__);
			return -EPERM;
		}
	}
	return 0;
}

/*
 * vxge_snmp_exit : removes the proc entry for mib objects
 * @vdev : reference to vxge private structure
 * Description : the function will be called when the pci
 * device is removed. it will remove the proc entries if all
 * of the devices are removed.
 */
static void vxge_snmp_exit(void)
{
	struct proc_dir_entry *mib;

	mib = vxge_proc_entry_check(proc_net, VXGE_PROC_MIB_DIR);
	if (!mib)
		return;

	remove_proc_entry(VXGE_PROC_BASE_FILE, mib);
	remove_proc_entry(VXGE_PROC_DEV_FILE, mib);
	if (!mib->subdir)
		remove_proc_entry(VXGE_PROC_MIB_DIR, proc_net);
}
#endif /* SNMP */

static inline u32 vxge_get_num_vfs(u64 function_mode)
{
	u32 num_functions = 0;

	switch (function_mode) {
	case VXGE_HW_FUNCTION_MODE_MULTI_FUNCTION:
	case VXGE_HW_FUNCTION_MODE_SRIOV_8:
	case VXGE_HW_FUNCTION_MODE_MULTI_FUNCTION_DIRECT_IO:
		num_functions = 8;
		break;
	case VXGE_HW_FUNCTION_MODE_SINGLE_FUNCTION:
		num_functions = 1;
		break;
	case VXGE_HW_FUNCTION_MODE_SRIOV:
	case VXGE_HW_FUNCTION_MODE_MRIOV:
	case VXGE_HW_FUNCTION_MODE_MULTI_FUNCTION_17:
		num_functions = 17;
		break;
	case VXGE_HW_FUNCTION_MODE_SRIOV_4:
		num_functions = 4;
		break;
	case VXGE_HW_FUNCTION_MODE_MULTI_FUNCTION_2:
		num_functions = 2;
		break;
	case VXGE_HW_FUNCTION_MODE_MRIOV_8:
		num_functions = 8; /* TODO */
		break;
	}
	return num_functions;
}

/**
 * vxge_probe
 * @pdev : structure containing the PCI related information of the device.
 * @pre: List of PCI devices supported by the driver listed in vxge_id_table.
 * Description:
 * This function is called when a new PCI device gets detected and initializes
 * it.
 * Return value:
 * returns 0 on success and negative on failure.
 *
 */
static int __devinit
vxge_probe(struct pci_dev *pdev, const struct pci_device_id *pre)
{
	struct __vxge_hw_device *hldev = NULL;
	enum vxge_hw_status status;
	int ret;
	int high_dma = 0;
	u64 vpath_mask = 0;
	struct vxgedev *vdev = NULL;
	struct vxge_config ll_config;
	struct vxge_hw_device_config *device_config = NULL;
	struct vxge_hw_device_attr attr;
	struct vxge_hw_device_version *fw_version;
	int vf_idx, i, j, no_of_vpath = 0, max_vpath_supported = 0;
	u8 *macaddr, revision, titan1;
	struct vxge_mac_addrs *entry;
	static int bus = -1, device = -1;
	u8 new_device = 0;
	u32 host_type;
	enum vxge_hw_status is_privileged;
	u32 fw_version_current = 0;
	u64 eprom_img_ver_current[8];
	u16 eprom_img_type = 0;
	u32 function_mode;
	u8 reboot_req = 0;
	u32 fw_ver_maj_min = 0;
	u32 num_vfs = 0;
	u16 link_width;

	vxge_debug_entryexit(VXGE_TRACE, "%s:%d", __func__, __LINE__);
	attr.pdev = pdev;

	if (
#ifdef CONFIG_PCI_IOV
		/* In SRIOV-17 mode, functions of the same adapter
		 * can be deployed on different buses */
		(!pdev->is_virtfn) &&
#endif
		((bus != pdev->bus->number) ||
		(device != PCI_SLOT(pdev->devfn))))
		new_device = 1;

	bus = pdev->bus->number;
	device = PCI_SLOT(pdev->devfn);

	if (new_device) {
		if (driver_config->config_dev_cnt &&
		   (driver_config->config_dev_cnt !=
			driver_config->total_dev_cnt))
			vxge_debug_init(VXGE_ERR,
				"%s: Configured %d of %d devices",
				VXGE_DRIVER_NAME,
				driver_config->config_dev_cnt,
				driver_config->total_dev_cnt);
		driver_config->config_dev_cnt = 0;
		driver_config->total_dev_cnt = 0;
	}

	if (pci_msix_table_size(pdev) <= 1) {
		pci_set_drvdata(pdev, NULL);
		return -EINVAL;
	}

	driver_config->vpath_per_dev = max_config_vpath;

	driver_config->total_dev_cnt++;
	if (++driver_config->config_dev_cnt > max_config_dev) {

		ret = 0;

		printk("%s: Use max_config_dev option to load "
			"%02d:%02d.%d function\n",
			VXGE_DRIVER_NAME, bus, device, PCI_FUNC(pdev->devfn));
		goto _exit0;
	}

	device_config = kzalloc(sizeof(struct vxge_hw_device_config),
		GFP_KERNEL);
	if (!device_config) {
		ret = -ENOMEM;
		vxge_debug_init(VXGE_ERR,
			"device_config : malloc failed %s %d",
			__FILE__, __LINE__);
		goto _exit0;
	}

	memset(&ll_config, 0, sizeof(struct vxge_config));

	if (tx_steering_type == VXGE_USE_DEFAULT) {
		if ((bw[driver_config->total_dev_cnt-1] !=
			VXGE_HW_VPATH_TX_BW_LIMIT_DEFAULT)
#if (VXGE_CERT_FW_VER < VXGE_FW_VER(1, 8, 0))
			|| (tx_bw[driver_config->total_dev_cnt-1] !=
			VXGE_HW_VPATH_TX_BW_LIMIT_DEFAULT)
#endif
			)
			ll_config.tx_steering_type = NO_STEERING;
		else {
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 26)) || (defined(ESX_KL) && defined(__VMKNETDDI_QUEUEOPS__))
			ll_config.tx_steering_type = TX_MULTIQ_STEERING;
#else
			ll_config.tx_steering_type = TX_PORT_STEERING;
#endif
		}
	} else
		ll_config.tx_steering_type = tx_steering_type;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 23))
	if (ll_config.tx_steering_type == TX_MULTIQ_STEERING) {
		vxge_debug_init(VXGE_ERR,
			"%s : MultiQ is not supported on this kernel",
			__func__);
		ll_config.tx_steering_type = TX_PORT_STEERING;
	}
#elif (LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 26))
#ifndef CONFIG_NETDEVICES_MULTIQUEUE
	if (ll_config.tx_steering_type == TX_MULTIQ_STEERING) {
		vxge_debug_init(VXGE_ERR,
			"%s : MultiQ is not supported on this kernel",
			__func__);
		ll_config.tx_steering_type = TX_PORT_STEERING;
	}
#endif

#endif

	if (lro == VXGE_HW_GRO_ENABLE) {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29))
		lro = VXGE_HW_LRO_DONT_AGGR_FWD_PKTS;
#endif
	}
	ll_config.intr_type = intr_type;
	ll_config.catch_basin_mode = VXGE_CATCH_BASIN_MODE_ALWAYS_DYNAMIC;

	pci_read_config_byte(pdev, PCI_REVISION_ID, &revision);

	titan1 = is_titan1(pdev->device, revision);

	ll_config.rx_steering_type = rx_steering_type;

	/* if Any s_vid is configured disallow promisc_mode on VF's */
	for (vf_idx = 0; vf_idx < VXGE_HW_MAX_VIRTUAL_FUNCTIONS; vf_idx++) {
		if ((svlan_id[vf_idx] != VXGE_HW_SVLAN_ID_DEFAULT)
			&& (promisc_all_en)) {
			vxge_debug_init(VXGE_ERR,
			"%s : S_VID is configured, promisc mode on VF not"
			" allowed", __func__);
			promisc_all_en = VXGE_HW_PROM_MODE_DISABLE;
		}
	}

	ll_config.promisc_en = promisc_en;
	ll_config.promisc_all_en = promisc_all_en;
	ll_config.ack_aggr = ack_aggr;

	/* get the default configuration parameters */
	vxge_hw_device_config_default_get(device_config);

	/* initialize configuration parameters */
	vxge_device_config_init(device_config, &ll_config.intr_type);

	ret = pci_enable_device(pdev);
	if (ret) {
		vxge_debug_init(VXGE_ERR,
			"%s : can not enable PCI device", __func__);
		goto _exit0;
	}

	if (!pci_set_dma_mask(pdev, DMA_BIT_MASK(64))) {
		vxge_debug_ll_config(VXGE_TRACE,
			"%s : using 64bit DMA", __func__);

		high_dma = 1;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 0))
		if (pci_set_consistent_dma_mask(pdev,
						DMA_BIT_MASK(64))) {
			vxge_debug_init(VXGE_ERR,
				"%s : unable to obtain 64bit DMA for "
				"consistent allocations", __func__);
			ret = -ENOMEM;
			goto _exit1;
		}
#endif
	} else if (!pci_set_dma_mask(pdev, DMA_BIT_MASK(32))) {
		vxge_debug_ll_config(VXGE_TRACE,
			"%s : using 32bit DMA", __func__);
	} else {
		ret = -ENOMEM;
		goto _exit1;
	}

	if (pci_request_region(pdev, 0, VXGE_DRIVER_NAME)) {
		vxge_debug_init(VXGE_ERR,
			"%s : request regions failed", __func__);
		ret = -ENODEV;
		goto _exit1;
	}

	pci_set_master(pdev);

	attr.bar0 = vxge_pci_ioremap_bar(pdev, 0);
	if (!attr.bar0) {
		vxge_debug_init(VXGE_ERR,
			"%s : cannot remap io memory bar0", __func__);
		ret = -ENODEV;
		goto _exit2;
	}
	vxge_debug_ll_config(VXGE_TRACE,
		"pci ioremap bar0: %p:0x%llx",
		attr.bar0,
		(unsigned long long)pci_resource_start(pdev, 0));

	status = vxge_hw_device_hw_info_get(pdev, attr.bar0,
			&ll_config.device_hw_info);
	if (status != VXGE_HW_OK) {
		vxge_debug_init(VXGE_ERR,
			"%s: Reading of hardware info failed."
			"Please try upgrading the firmware.", VXGE_DRIVER_NAME);
		ret = -EINVAL;
		goto _exit3;
	}

	vpath_mask = ll_config.device_hw_info.vpath_mask;
	if (vpath_mask == 0) {
		vxge_debug_ll_config(VXGE_TRACE,
			"%s: No vpaths available in device", VXGE_DRIVER_NAME);
		ret = -EINVAL;
		goto _exit3;
	}
	vxge_debug_ll_config(VXGE_TRACE,
		"%s:%d  Vpath mask = %llx", __func__, __LINE__,
		(unsigned long long)vpath_mask);

	host_type = ll_config.device_hw_info.host_type;
	is_privileged = __vxge_hw_device_is_privilaged(host_type,
		ll_config.device_hw_info.func_id);

	fw_version = &ll_config.device_hw_info.fw_version;
	fw_version_current = VXGE_FW_VER(fw_version->major, fw_version->minor,
		fw_version->build);

	fw_ver_maj_min = VXGE_MAJ_MIN_FW_VER(fw_version->major,
				fw_version->minor);

	/* Fail the driver load, if the firmware version is less than
	 * 1.4.4 (supports firmware upgrade)
	 */
	if (fw_version_current != VXGE_CERT_FW_VER) {
		printk(KERN_ALERT "%s: Current firmware version: "
			"%d.%d.%d\n",VXGE_DRIVER_NAME, fw_version->major,
			fw_version->minor,fw_version->build);
		if (fw_version_current < VXGE_BASE_FW_VER) {

			printk(KERN_ALERT "%s: Driver load failed due to "
				"incompatible firmware in adapter\n",
				VXGE_DRIVER_NAME);

			printk(KERN_ALERT
				"%s: Please upgrade firmware to version "
				"%d.%d.%d\n", VXGE_DRIVER_NAME,
				VXGE_CERT_FW_VER_MAJOR, VXGE_CERT_FW_VER_MINOR,
				VXGE_CERT_FW_VER_BUILD);

			printk(KERN_ALERT "%s: Firmware upgrade instructions in "
				"README\n", VXGE_DRIVER_NAME);

			ret = -EACCES;
			goto _exit3;
		}
	}

	/* FW_API_GET_EPROM_REV_API is supported from 1.6.1 onwards */
	if (VXGE_FW_VER(fw_version->major, fw_version->minor,
		fw_version->build) < VXGE_FW_VER(1, 6, 1))
		goto skip_eprom_ver_check;

	for (i = 0; i < VXGE_HW_MAX_ROM_IMAGES; i++) {

		if (!ll_config.device_hw_info.eprom_image_data[i].is_valid)
			break;

		eprom_img_ver_current[i] = (u64)
			ll_config.device_hw_info.eprom_image_data[i].version;

		if (eprom_img_ver_current[i] !=
			vxge_cert_eprom_image_version[i]) {
			printk(KERN_ALERT
				"%s: Current %s image version: "
				"%llx.%llx.%llx.%llx \n",VXGE_DRIVER_NAME,
				vxge_eprom_image_type[eprom_img_type],
				VXGE_EPROM_IMG_MAJOR(eprom_img_ver_current[i]),
				VXGE_EPROM_IMG_MINOR(eprom_img_ver_current[i]),
				VXGE_EPROM_IMG_FIX(eprom_img_ver_current[i]),
				VXGE_EPROM_IMG_BUILD(eprom_img_ver_current[i]));

			if (fw_version_current < VXGE_BASE_FW_VER) {

				printk(KERN_ALERT "%s: Driver load failed due"
					"to incompatible eprom image%d in"
					"adapter\n", VXGE_DRIVER_NAME, i);

				printk(KERN_ALERT
					"%s: Please upgrade eprom image"
					"to version %x\n", VXGE_DRIVER_NAME,
					vxge_cert_eprom_image_version[i]);

				printk(KERN_ALERT "%s: eprom image upgrade"
					"instructions in README\n",
					VXGE_DRIVER_NAME);

				ret = -EACCES;
				goto _exit3;
			}
		}
	}

skip_eprom_ver_check:
	/* Check how many vpaths are available */
	for (i = 0; i < VXGE_HW_MAX_VIRTUAL_PATHS; i++) {
		if (!((vpath_mask) & vxge_mBIT(i)))
			continue;
		max_vpath_supported++;
	}

	if ((driver_config->vpath_per_dev != VXGE_USE_DEFAULT) &&
			(max_vpath_supported < driver_config->vpath_per_dev)) {
		driver_config->vpath_per_dev = max_vpath_supported;
		vxge_debug_ll_config(VXGE_ERR,
			"Restricting no of vpath to %d \n",
					driver_config->vpath_per_dev);
	}

	ll_config.napi_enable = napi;

	/*
	 * Configure vpaths and get driver configured number of vpaths
	 * which is less than or equal to the maximum vpaths per function.
	 */
	no_of_vpath = vxge_config_vpaths(device_config, vpath_mask, &ll_config);
	if (!no_of_vpath) {
		vxge_debug_ll_config(VXGE_ERR,
			"%s: No more vpaths to configure", VXGE_DRIVER_NAME);

		ret = 0;

		goto _exit3;
	}

	if (no_of_vpath == 1) {
		vxge_debug_ll_config(VXGE_TRACE,
			"%s: Disable tx and rx steering, "
			"as single vpath is configured", VXGE_DRIVER_NAME);
		ll_config.tx_steering_type = NO_STEERING;
		ll_config.rx_steering_type = NO_STEERING;
	}

	/* GRO and NAPI are tied together. If GRO is enabled and NAPI is
	 * disabled switch to SW-LRO */
	if (lro && (lro == VXGE_HW_GRO_ENABLE) && (!ll_config.napi_enable))
		lro = VXGE_HW_LRO_DONT_AGGR_FWD_PKTS;

	if ((no_of_vpath == 1) && ll_config.napi_enable && lro &&
		(lro != VXGE_HW_GRO_ENABLE))
		for (i = 0; i < VXGE_HW_MAX_VIRTUAL_PATHS; i++)
			device_config->vp_config[i].aggr_ack =
				ll_config.ack_aggr;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24))
	else if ((ll_config.intr_type == MSI_X) && ll_config.napi_enable &&
		lro && (lro != VXGE_HW_GRO_ENABLE))
		for (i = 0; i < VXGE_HW_MAX_VIRTUAL_PATHS; i++)
			device_config->vp_config[i].aggr_ack =
				ll_config.ack_aggr;
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24))
	ll_config.napi_weight = OLD_NAPI_WEIGHT;
#else
	ll_config.napi_weight = NEW_NAPI_WEIGHT;
#endif
	/* Setting driver callbacks */
	attr.uld_callbacks.link_up = vxge_callback_link_up;
	attr.uld_callbacks.link_down = vxge_callback_link_down;
	attr.uld_callbacks.crit_err = vxge_callback_crit_err;

	status = vxge_hw_device_initialize(&hldev, &attr,
			device_config, titan1);
	if (status != VXGE_HW_OK) {
		vxge_debug_init(VXGE_ERR,
			"Failed to initialize device (%d)", status);
			ret = -EINVAL;
			goto _exit3;
	}

	hldev->fw_version = fw_version_current;

	for (i = 0; i < VXGE_HW_MAX_ROM_IMAGES; i++) {
		if (!ll_config.device_hw_info.eprom_image_data[i].is_valid)
			break;
		hldev->eprom_versions[i] =
			ll_config.device_hw_info.eprom_image_data[i].version;
	}

	/* set to factory default configuration */
	if ((is_privileged == VXGE_HW_OK) &&
			(factory_default != VXGE_USE_DEFAULT)) {
		status = vxge_hw_config_restore_defaults(hldev);
		printk(KERN_ALERT
			"%s: Config restore defaults %s."
			"Power cycle of system required\n", VXGE_DRIVER_NAME,
			(status == VXGE_HW_FAIL) ? "failed" : "succeeded");
			driver_config->config_dev_cnt++;
			max_config_dev = 1;
			ret = -EACCES;
			goto _exit4;
	}

	/*
	 * Upgrade the firmware on the PF if the user option to upgrade
	 * the firmware is a 'force' or the major plus minor versions
	 * are less than the certified version.
	 * So, if the driver and adapter major plus minor revisions are
	 * the same while the build revision is different, a firmware
	 * upgrade is not required unless the user specifies a force
	 * upgrade option.
	 */
	if ((fw_upgrade) && ((fw_upgrade >= VXGE_HW_FW_UPGRADE_FORCE) ||
		(fw_version_current != VXGE_CERT_FW_VER))) {

		/*
		 * From fw_ver 1.8.1 and above ignore the build number.
		 */
		if ((fw_upgrade == VXGE_HW_FW_UPGRADE_ALL) &&
			((fw_version_current >= VXGE_FW_VER(1, 8, 1)) &&
			(fw_ver_maj_min == VXGE_CERT_MAJ_MIN_FW_VER)))
			goto continue_load;

		/*
		 * If it is force upgrade with PXE option and if the version of
		 * both firmware and gPXE are same as certified version,
		 * do not upgrade the fw. If either of them is different
		 * then go ahead with the upgrade.
		 */
		if (fw_upgrade == VXGE_HW_FW_UPGRADE_FORCE) {
			if ((fw_version_current == VXGE_CERT_FW_VER) &&
				(fw_version_current >= VXGE_FW_VER(1, 6, 1))) {
				for (i = 0; i < VXGE_HW_MAX_ROM_IMAGES; i++) {
					if (!ll_config.device_hw_info.
						eprom_image_data[i].is_valid) {
						if (i == 0)
							goto continue_upgrade;
						else
							break;
					}
					eprom_img_ver_current[i] =
						ll_config.device_hw_info.
						eprom_image_data[i].version;

					if (eprom_img_ver_current[i] !=
					 vxge_cert_eprom_image_version[i])
						goto continue_upgrade;
				}
				goto continue_load;
			}
		}
		/*
		 * If it is force upgrade w/o PXE option and if the adapter's
		 * version of firmware is same as certified version, do not
		 * upgrade the fw. Upgrade only if adapter has a gPXE image.
		 */
		else if (fw_upgrade == VXGE_HW_FW_UPGRADE_WO_PXE_FORCE) {
			 if ((fw_version_current == VXGE_CERT_FW_VER) &&
				(fw_version_current >= VXGE_FW_VER(1, 6, 1))) {
				for (i = 0; i < VXGE_HW_MAX_ROM_IMAGES; i++)
					if (ll_config.device_hw_info.
						eprom_image_data[i].is_valid)
						break;
				if (i ==  VXGE_HW_MAX_ROM_IMAGES)
					goto continue_load;
			}
		}
continue_upgrade:
		/*
		 * If VF loads first which could be the case in shared io,
		 * then fail the corresponding driver load and let the PF
		 * take care of the firmware upgrade.
		 */
		if (is_privileged == VXGE_HW_ERR_PRIVILAGED_OPEARATION) {
			ret = -EACCES;
			printk(KERN_ALERT "%s: Driver load for VF failed"
			" due to Firmware mismatch. Load the driver"
			" on PF to upgrade to the correct firmware version.\n",
			VXGE_DRIVER_NAME);
			goto _exit4;
		}

		printk(KERN_ALERT "%s: Upgrading firmware to %d.%d.%d \n",
			VXGE_DRIVER_NAME,  VXGE_CERT_FW_VER_MAJOR,
			VXGE_CERT_FW_VER_MINOR, VXGE_CERT_FW_VER_BUILD);

		status = vxge_fw_upgrade(hldev);

		printk(KERN_ALERT
			"%s: FW upgrade %s\n", VXGE_DRIVER_NAME,
			(status == VXGE_HW_FAIL) ? "failed" : "succeeded. "
			"POWER CYCLE OF SYSTEM REQUIRED.");

		/*
		 * Don't load other functions
		 */
		driver_config->config_dev_cnt++;
		max_config_dev = 1;
		ret = -EACCES;
		goto _exit4;
	}

continue_load:
	/*
	 * Fail the load if the firmware major or minor version is above
	 * certified version.
	 */
	if (fw_ver_maj_min > VXGE_CERT_MAJ_MIN_FW_VER) {
		printk(KERN_ALERT "%s: Driver load failed!\n",
			VXGE_DRIVER_NAME);

		printk(KERN_ALERT "%s: Please upgrade driver to support "
			"newer adapter firmware: %d.%d.%d\n", VXGE_DRIVER_NAME,
			fw_version->major, fw_version->minor,
	                fw_version->build);

		ret = -EACCES;
		goto _exit4;
	}

	if (is_privileged == VXGE_HW_OK) {
		reboot_req = record_persist_config(hldev);
		if (reboot_req) {
			printk(KERN_ALERT "%s: Power cycle of system required."
				"\n", VXGE_DRIVER_NAME);
			/* don't load other functions */
			driver_config->config_dev_cnt++;
			max_config_dev = 1;
			ret = -EACCES;
			goto _exit4;
		}
	}

	/* if FCS stripping is not disabled in MAC fail driver load */
	if (vxge_hw_vpath_strip_fcs_check(hldev, vpath_mask) != VXGE_HW_OK) {
		vxge_debug_init(VXGE_ERR, "%s: FCS stripping is enabled in MAC"
				" failing driver load", VXGE_DRIVER_NAME);
		ret = -EINVAL;
		goto _exit4;
	}
	vxge_hw_device_debug_set(hldev, VXGE_ERR, VXGE_COMPONENT_LL);

	/* Read function mode */
	status = vxge_hw_get_func_mode(hldev, &function_mode);
	if (status != VXGE_HW_OK)
		goto _exit4;

	ll_config.device_hw_info.function_mode = function_mode;

	if (new_device && (is_privileged == VXGE_HW_OK))
		num_vfs = vxge_get_num_vfs(function_mode) - 1;

#ifdef CONFIG_PCI_IOV
	/* Enable SRIOV mode, if the firmware supports it and if it is a PF */
	if (is_sriov(function_mode) && !is_sriov_initialize(pdev) &&
		(ll_config.intr_type != INTA) &&
		(is_privileged == VXGE_HW_OK)) {

		ret = pci_enable_sriov(pdev, num_vfs);
		if (ret)
			vxge_debug_ll_config(VXGE_ERR,
				"%s: Failed in enabling SRIOV mode \n",
				VXGE_DRIVER_NAME);
	}
#endif
	/* set private device info */
	pci_set_drvdata(pdev, hldev);

	ll_config.lro_enable = lro;
	if (titan1)
		ll_config.lro_max_bytes = VXGE_LRO_MAX_BYTES;
	else
		ll_config.lro_max_bytes = VXGE_T1A_LRO_MAX_BYTES;

	ll_config.fifo_indicate_max_pkts = VXGE_FIFO_INDICATE_MAX_PKTS;
	ll_config.rec_all_vid = rec_all_vid;
	ll_config.rth_algorithm = RTH_ALG_JENKINS;

	switch (ll_config.rx_steering_type) {
	case RTH_TCP_UDP_STEERING:
		ll_config.rth_hash_type_tcpipv4 = 1;
		break;
	case RTH_IPV4_STEERING:
		ll_config.rth_hash_type_ipv4 = 1;
		break;
	case RTH_IPV6_EX_STEERING:
		ll_config.rth_hash_type_ipv6ex = 1;
		break;
	}

	ll_config.rth_hash_type_tcpipv6 = 0;
	ll_config.rth_hash_type_ipv6 = 0;
	ll_config.rth_hash_type_tcpipv6ex = 0;

	ll_config.rth_bkt_sz = RTH_BUCKET_SIZE;
	ll_config.tx_pause_enable = tx_pause_enable;
	ll_config.rx_pause_enable = rx_pause_enable;

	if (vxge_device_register(hldev, &ll_config, high_dma, no_of_vpath,
		&vdev)) {
		ret = -EINVAL;
		goto _exit4;
	}

	vxge_hw_device_debug_set(hldev, VXGE_TRACE, VXGE_COMPONENT_LL);
	VXGE_COPY_DEBUG_INFO_TO_LL(vdev, vxge_hw_device_error_level_get(hldev),
		vxge_hw_device_trace_level_get(hldev));

	/* set private HW device info */
	hldev->ndev = vdev->ndev;
	hldev->vdev = vdev;
	vdev->mtu = VXGE_HW_DEFAULT_MTU;
	vdev->bar0 = attr.bar0;
	vdev->no_of_vpath = no_of_vpath;
	vdev->titan1 = titan1;
	vdev->priv_fun_num = 0xFF;

	vdev->max_rx_buffer_size = vdev->mtu;

	/* Virtual Path count */
	for (i = 0, j = 0; i < VXGE_HW_MAX_VIRTUAL_PATHS; i++) {
		if (!vxge_bVALn(vpath_mask, i, 1))
			continue;
		if (j >= vdev->no_of_vpath)
			break;

		vdev->vpaths[j].is_configured = 1;
		vdev->vpaths[j].device_id = i;
#if ((LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 26)) && \
	defined(CONFIG_NETDEVICES_MULTIQUEUE))
		vdev->vpaths[j].fifo.driver_id = j;
#endif
		vdev->vpaths[j].ring.driver_id = j;
		vdev->vpaths[j].ring.rx_vlan_stripped = FALSE;
		vdev->vpaths[j].vdev = vdev;
		vdev->vpaths[j].max_mac_addr_cnt = max_mac_vpath;
		memcpy((u8 *)vdev->vpaths[j].macaddr,
				(u8 *)ll_config.device_hw_info.mac_addrs[i],
				ETH_ALEN);

		/* Initialize the mac address list header */
		INIT_LIST_HEAD(&vdev->vpaths[j].mac_addr_list);

		vdev->vpaths[j].mac_addr_cnt = 0;
		vdev->vpaths[j].mcast_addr_cnt = 0;
		j++;
	}
	vdev->exec_mode = exec_mode;

	/* if s_vid is configured disallow vlan_tag_strip
	 * disable configuration.
	 */
	if (svlan_id[hldev->func_id] != VXGE_HW_SVLAN_ID_DEFAULT) {
		if (vlan_tag_strip ==
			VXGE_HW_VPATH_RPA_STRIP_VLAN_TAG_DISABLE) {
			vxge_debug_init(VXGE_ERR,
				"%s : S_VID is configured, Can not disable \
				vlan_tag_strip\n", vdev->ndev->name);
			vlan_tag_strip =
				VXGE_HW_VPATH_RPA_STRIP_VLAN_TAG_ENABLE;
		}
	}

	vdev->vlan_tag_strip = vlan_tag_strip;

	/* map the hashing selector table to the configured vpaths */
	for (i = 0; i < vdev->no_of_vpath; i++)
		vdev->vpath_selector[i] = vpath_selector[i];

	macaddr = (u8 *)vdev->vpaths[0].macaddr;

	ll_config.device_hw_info.serial_number[VXGE_HW_INFO_LEN - 1] = '\0';
	ll_config.device_hw_info.product_desc[VXGE_HW_INFO_LEN - 1] = '\0';
	ll_config.device_hw_info.part_number[VXGE_HW_INFO_LEN - 1] = '\0';

	vxge_debug_init(VXGE_TRACE, "%s: Neterion %s Server Adapter",
		vdev->ndev->name, ll_config.device_hw_info.product_desc);

	vxge_debug_init(VXGE_TRACE, "%s: SERIAL NUMBER: %s",
		vdev->ndev->name, ll_config.device_hw_info.serial_number);

	vxge_debug_init(VXGE_TRACE, "%s: PART NUMBER: %s",
		vdev->ndev->name, ll_config.device_hw_info.part_number);

	vxge_debug_init(VXGE_TRACE,
		"%s: MAC ADDR: %02X:%02X:%02X:%02X:%02X:%02X",
		vdev->ndev->name, macaddr[0], macaddr[1], macaddr[2],
		macaddr[3], macaddr[4], macaddr[5]);

	link_width = vxge_hw_device_link_width_get(hldev);
	if (link_width > 0)
		vxge_debug_init(VXGE_TRACE, "%s: Link Width x%d",
			vdev->ndev->name, link_width);

	vxge_debug_init(VXGE_TRACE,
		"%s: Firmware version : %s Date : %s", vdev->ndev->name,
		ll_config.device_hw_info.fw_version.version,
		ll_config.device_hw_info.fw_date.date);

	for (i = 0; i < VXGE_HW_MAX_ROM_IMAGES; i++) {
		if (!ll_config.device_hw_info.eprom_image_data[i].is_valid)
			break;
		printk(KERN_ALERT
			"%s: %s image version: "
			"%llx.%llx.%llx.%llx \n",VXGE_DRIVER_NAME,
			vxge_eprom_image_type[eprom_img_type],
			VXGE_EPROM_IMG_MAJOR(eprom_img_ver_current[i]),
			VXGE_EPROM_IMG_MINOR(eprom_img_ver_current[i]),
			VXGE_EPROM_IMG_FIX(eprom_img_ver_current[i]),
			VXGE_EPROM_IMG_BUILD(eprom_img_ver_current[i]));
	}

	vxge_debug_init(VXGE_TRACE, "%s: %s Enabled",
			vdev->ndev->name,
			vxge_func_mode_names[function_mode]);

	if (new_device && (is_privileged == VXGE_HW_OK))
		vdev->num_functions = vxge_get_num_vfs(function_mode);

	vxge_print_parm(vdev, vpath_mask);

	/* Store the fw version for ethttool option */
	strcpy(vdev->fw_version, ll_config.device_hw_info.fw_version.version);
	memcpy(vdev->ndev->dev_addr, (u8 *)vdev->vpaths[0].macaddr, ETH_ALEN);
#ifdef ETHTOOL_GPERMADDR
	memcpy(vdev->ndev->perm_addr, vdev->ndev->dev_addr, ETH_ALEN);
#endif
	/* Copy the station mac address to the list */
	for (i = 0; i < vdev->no_of_vpath; i++) {
		entry =	(struct vxge_mac_addrs *)
				kzalloc(sizeof(struct vxge_mac_addrs),
					GFP_KERNEL);
		if (NULL == entry) {
			vxge_debug_init(VXGE_ERR,
				"%s: mac_addr_list : memory allocation failed",
				vdev->ndev->name);
			ret = -EPERM;
			goto _exit5;
		}
		macaddr = (u8 *)&entry->macaddr;
		memcpy(macaddr, vdev->ndev->dev_addr, ETH_ALEN);
		list_add(&entry->item, &vdev->vpaths[i].mac_addr_list);
		vdev->vpaths[i].mac_addr_cnt = 1;
	}

	/* disable address learning */
	vdev->config.addr_learn_en = DISABLE_ADDR_LEARNING;
	spin_lock_init(&vdev->addr_learn_lock);

	vxge_hw_device_debug_set(hldev, VXGE_ERR, VXGE_COMPONENT_LL);
	VXGE_COPY_DEBUG_INFO_TO_LL(vdev, vxge_hw_device_error_level_get(hldev),
		vxge_hw_device_trace_level_get(hldev));

	kfree(device_config);

	/*
	 * INTA is shared in multi-function mode. This is unlike the INTA
	 * implementation in MR mode, where each VH has its own INTA message.
	 * - INTA is masked (disabled) as long as at least one function sets
	 * its TITAN_MASK_ALL_INT.ALARM bit.
	 * - INTA is unmasked (enabled) when all enabled functions have cleared
	 * their own TITAN_MASK_ALL_INT.ALARM bit.
	 * The TITAN_MASK_ALL_INT ALARM & TRAFFIC bits are cleared on power up.
	 * Though this driver leaves the top level interrupts unmasked while
	 * leaving the required module interrupt bits masked on exit, there
	 * could be a rougue driver around that does not follow this procedure
	 * resulting in a failure to generate interrupts. The following code is
	 * present to prevent such a failure.
	 */

	if (is_mf(function_mode))
		if (vdev->config.intr_type == INTA)
			vxge_hw_device_unmask_all(hldev);

	/* Configure Bandwidth, Priority and flow control */
	if (is_privileged == VXGE_HW_OK) {
		/* configure bandwidth */
		vxge_update_rx_bw(vdev);
		vxge_update_tx_bw(vdev);

		/* Configure priority */
		vxge_update_priority(vdev);

		/* Set flow control */
		vxge_hw_device_set_flow_ctrl(vdev->devh,
				vdev->config.tx_pause_enable,
				vdev->config.rx_pause_enable);
	}

	vxge_debug_entryexit(VXGE_TRACE, "%s: %s:%d  Exiting...",
		vdev->ndev->name, __func__, __LINE__);

	return 0;

_exit5:
	for (i = 0; i < vdev->no_of_vpath; i++)
		vxge_free_mac_add_list(&vdev->vpaths[i]);

	vxge_device_unregister(hldev);
_exit4:
	vxge_hw_device_terminate(hldev);
#ifdef CONFIG_PCI_IOV
	pci_disable_sriov(pdev);
#endif
_exit3:
	iounmap(attr.bar0);

_exit2:
	pci_release_region(pdev, 0);
_exit1:
	/* This error code is reserved for fw check error, in which case the
	 * device will be left in enabled state for upgrading the firmware
	 */
	if (ret != -EACCES)
		pci_disable_device(pdev);
_exit0:
	kfree(device_config);
	driver_config->config_dev_cnt--;

	printk(KERN_ALERT "%s: WARNING!! Driver not loaded for %02d:%02d.%d"
		" function!!\n", VXGE_DRIVER_NAME, bus, device,
		PCI_FUNC(pdev->devfn));

	pci_set_drvdata(pdev, NULL);

	return ret;
}

/**
 * vxge_rem_nic - Free the PCI device
 * @pdev: structure containing the PCI related information of the device.
 * Description: This function is called by the Pci subsystem to release a
 * PCI device and free up all resource held up by the device.
 */
static void __devexit
vxge_remove(struct pci_dev *pdev)
{
	struct __vxge_hw_device  *hldev;
	struct vxgedev *vdev = NULL;
	struct net_device *dev;
	int i = 0, no_of_vpath;
#if ((VXGE_DEBUG_INIT & VXGE_DEBUG_MASK) || \
	(VXGE_DEBUG_ENTRYEXIT & VXGE_DEBUG_MASK))
	u32 level_trace;
#endif

	hldev = (struct __vxge_hw_device  *) pci_get_drvdata(pdev);

	if (hldev == NULL)
		return;
	dev = hldev->ndev;
	vdev = netdev_priv(dev);

#if ((VXGE_DEBUG_INIT & VXGE_DEBUG_MASK) || \
	(VXGE_DEBUG_ENTRYEXIT & VXGE_DEBUG_MASK))
	level_trace = vdev->level_trace;
#endif
	vxge_debug_entryexit(level_trace,
		"%s:%d", __func__, __LINE__);

	vxge_debug_init(level_trace,
		"%s : removing PCI device...", __func__);
	vxge_device_unregister(hldev);

	no_of_vpath = vdev->no_of_vpath;
	for (i = 0; i < vdev->no_of_vpath; i++) {
		vxge_free_mac_add_list(&vdev->vpaths[i]);
		vdev->vpaths[i].mcast_addr_cnt = 0;
		vdev->vpaths[i].mac_addr_cnt = 0;
	}

	kfree(vdev->vpaths);

	iounmap(vdev->bar0);

	/* we are safe to free it now */
	free_netdev(dev);

	vxge_debug_init(level_trace,
		"%s:%d  Device unregistered", __func__, __LINE__);

	vxge_hw_device_terminate(hldev);

	pci_disable_device(pdev);
	pci_release_region(pdev, 0);
	pci_set_drvdata(pdev, NULL);

	vxge_debug_entryexit(level_trace,
		"%s:%d  Exiting...", __func__, __LINE__);
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 21))
static struct pci_error_handlers vxge_err_handler = {
	.error_detected = vxge_io_error_detected,
	.slot_reset = vxge_io_slot_reset,
	.resume = vxge_io_resume,
};
#endif

static struct pci_driver vxge_driver = {
	.name = VXGE_DRIVER_NAME,
	.id_table = vxge_id_table,
	.probe = vxge_probe,
	.remove = __devexit_p(vxge_remove),
#ifdef CONFIG_PM
	.suspend = vxge_pm_suspend,
	.resume = vxge_pm_resume,
#endif
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 21))
	.err_handler = &vxge_err_handler,
#endif
};

static int __init
vxge_starter(void)
{
	int ret = 0;
	char version[32];

	snprintf(version, 32, "%s", DRV_VERSION);

	printk(KERN_CRIT "%s: Copyright(c) 2002-2010 Exar Corp.\n",
		VXGE_DRIVER_NAME);
	printk(KERN_CRIT "%s: Driver version: %s\n",
			VXGE_DRIVER_NAME, version);

	ret = pci_register_driver(&vxge_driver);
	if (ret)
		goto err;

	if (driver_config->config_dev_cnt &&
	   (driver_config->config_dev_cnt != driver_config->total_dev_cnt))
		vxge_debug_init(VXGE_ERR,
			"%s: Configured %d of %d devices",
			VXGE_DRIVER_NAME, driver_config->config_dev_cnt,
			driver_config->total_dev_cnt);
#ifdef VXGE_SNMP
	vxge_snmp_init();
#endif
err:
	return ret;
}

static void __exit
vxge_closer(void)
{
#ifdef VXGE_SNMP
	vxge_snmp_exit();
#endif
	pci_unregister_driver(&vxge_driver);
}
module_init(vxge_starter);
module_exit(vxge_closer);
