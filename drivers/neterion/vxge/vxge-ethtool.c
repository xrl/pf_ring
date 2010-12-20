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
 * vxge-ethtool.c: Driver for Neterion Inc's X3100 Series 10GbE PCIe I/O
 *                 Virtualized Server Adapter.
 * Copyright(c) 2002-2010 Exar Corp.
 ******************************************************************************/
#include<linux/netdevice.h>
#include<linux/ethtool.h>
#include <linux/pci.h>
#include <linux/etherdevice.h>
#include <linux/version.h>
#include <linux/delay.h>
#include <asm/uaccess.h>
#include "vxge-main.h"
#include "vxge-kcompat.h"
#include "vxge-ethtool.h"

/**
 * vxge_ethtool_sset - Sets different link parameters.
 * @dev: device pointer.
 * @info: pointer to the structure with parameters given by ethtool to set
 * link information.
 *
 * The function sets different link parameters provided by the user onto
 * the NIC.
 * Return value:
 * 0 on success.
 */

static int vxge_ethtool_sset(struct net_device *dev, struct ethtool_cmd *info)
{
	/* We currently only support 10Gb/FULL */
	if ((info->autoneg == AUTONEG_ENABLE) ||
	    (info->speed != SPEED_10000) || (info->duplex != DUPLEX_FULL))
		return -EINVAL;

	return 0;
}

/**
 * vxge_ethtool_gset - Return link specific information.
 * @dev: device pointer.
 * @info: pointer to the structure with parameters given by ethtool
 * to return link information.
 *
 * Returns link specific information like speed, duplex etc.. to ethtool.
 * Return value :
 * return 0 on success.
 */
static int vxge_ethtool_gset(struct net_device *dev, struct ethtool_cmd *info)
{
	u32 rx_bw = 0, rx_prio = 0;
	enum vxge_hw_status status = VXGE_HW_OK;
	struct vxgedev *vdev = (struct vxgedev *)netdev_priv(dev);

	info->supported = (SUPPORTED_10000baseT_Full | SUPPORTED_FIBRE);
	info->advertising = (ADVERTISED_10000baseT_Full | ADVERTISED_FIBRE);
	info->port = PORT_FIBRE;

	info->transceiver = XCVR_EXTERNAL;
	info->autoneg = AUTONEG_DISABLE;

	if (vdev->devh->fw_version >= VXGE_FW_VER(1, 8, 0))
		status = vxge_hw_non_priv_func_rx_bw_get(vdev->devh,
							&rx_bw, &rx_prio);

	if (status == VXGE_HW_OK || (netif_carrier_ok(dev))) {
			info->speed = (rx_bw <= 0) ? SPEED_10000 : rx_bw;
			info->duplex = DUPLEX_FULL;
	} else {
		info->speed = -1;
		info->duplex = -1;
	}

	return 0;
}

/**
 * vxge_ethtool_gdrvinfo - Returns driver specific information.
 * @dev: device pointer.
 * @info: pointer to the structure with parameters given by ethtool to
 * return driver information.
 *
 * Returns driver specefic information like name, version etc.. to ethtool.
 */
static void vxge_ethtool_gdrvinfo(struct net_device *dev,
			struct ethtool_drvinfo *info)
{
	struct vxgedev *vdev;
	vdev = (struct vxgedev *)netdev_priv(dev);
	strlcpy(info->driver, VXGE_DRIVER_NAME, sizeof(VXGE_DRIVER_NAME));
	strlcpy(info->version, DRV_VERSION, sizeof(DRV_VERSION));
	strlcpy(info->fw_version, vdev->fw_version, VXGE_HW_FW_STRLEN);
	strlcpy(info->bus_info, pci_name(vdev->pdev), sizeof(info->bus_info));
	info->regdump_len = sizeof(struct vxge_hw_vpath_reg)
				* vdev->no_of_vpath;

	info->n_stats = STAT_LEN;
}

/**
 * vxge_ethtool_idnic - To physically identify the nic on the system.
 * @dev : device pointer.
 * @id : pointer to the structure with identification parameters given by
 * ethtool.
 *
 * Used to physically identify the NIC on the system.
 * The Link LED will blink for a time specified by the user.
 * Return value:
 * 0 on success
 */
static int vxge_ethtool_idnic(struct net_device *dev, u32 data)
{
	struct vxgedev *vdev = (struct vxgedev *)netdev_priv(dev);
	struct __vxge_hw_device  *hldev = (struct __vxge_hw_device  *)
			pci_get_drvdata(vdev->pdev);

	vxge_hw_device_flick_link_led(hldev, VXGE_FLICKER_ON);
	msleep_interruptible(data ? (data * HZ) : VXGE_MAX_FLICKER_TIME);
	vxge_hw_device_flick_link_led(hldev, VXGE_FLICKER_OFF);

	return 0;
}

/**
 * vxge_ethtool_getpause_data - Pause frame frame generation and reception.
 * @dev : device pointer.
 * @ep : pointer to the structure with pause parameters given by ethtool.
 * Description:
 * Returns the Pause frame generation and reception capability of the NIC.
 * Return value:
 *  void
 */
static void vxge_ethtool_getpause_data(struct net_device *dev,
					struct ethtool_pauseparam *ep)
{
	struct vxgedev *vdev = (struct vxgedev *)netdev_priv(dev);
	struct __vxge_hw_device  *hldev = (struct __vxge_hw_device  *)
			pci_get_drvdata(vdev->pdev);

	vxge_hw_device_getpause_data(hldev, 0, &ep->tx_pause, &ep->rx_pause);
}

/**
 * vxge_ethtool_setpause_data -  set/reset pause frame generation.
 * @dev : device pointer.
 * @ep : pointer to the structure with pause parameters given by ethtool.
 * Description:
 * It can be used to set or reset Pause frame generation or reception
 * support of the NIC.
 * Return value:
 * int, returns 0 on Success
 */
static int vxge_ethtool_setpause_data(struct net_device *dev,
					struct ethtool_pauseparam *ep)
{
	struct vxgedev *vdev = (struct vxgedev *)netdev_priv(dev);
	struct __vxge_hw_device  *hldev = (struct __vxge_hw_device  *)
			pci_get_drvdata(vdev->pdev);
	enum vxge_hw_status status;

	status = vxge_hw_device_set_flow_ctrl(hldev, 
				ep->tx_pause, ep->rx_pause);

	if (status == VXGE_HW_OK) {
		vdev->config.tx_pause_enable = ep->tx_pause;
		vdev->config.rx_pause_enable = ep->rx_pause;
	}

	return 0;
}

static int vxge_ethtool_get_stats_count(struct net_device *dev)
{
	struct vxgedev *vdev = (struct vxgedev *)netdev_priv(dev);

	int soft_stat_cnt = VXGE_SW_STATS_LEN;

	if (!vdev->config.lro_enable ||
		(vdev->config.lro_enable == VXGE_HW_GRO_ENABLE))
		soft_stat_cnt -= SOFT_LRO_STAT_CNT;

	return VXGE_TITLE_LEN +
		(VXGE_HW_MAC_MAX_WIRE_PORTS * VXGE_HW_AGGR_STATS_LEN) +
		(VXGE_HW_MAC_MAX_WIRE_PORTS * VXGE_HW_PORT_STATS_LEN) +
		(vdev->no_of_vpath * VXGE_HW_VPATH_TX_STATS_LEN) +
		(vdev->no_of_vpath * VXGE_HW_VPATH_RX_STATS_LEN) +

		(vdev->no_of_vpath * soft_stat_cnt) +
		DRIVER_STAT_LEN;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24))
static int vxge_ethtool_get_sset_count(struct net_device *dev, int sset)
{
	switch (sset) {
#ifdef VXGE_SELF_TEST
	case ETH_SS_TEST:
		return VXGE_TEST_LEN;
#endif
	case ETH_SS_STATS:
		return vxge_ethtool_get_stats_count(dev);
	default:
		return -EOPNOTSUPP;
	}
}
#endif

static void vxge_get_ethtool_stats(struct net_device *dev,
				   struct ethtool_stats *estats, u64 *tmp_stats)
{
	int j, k, count;
	enum vxge_hw_status status;
	enum vxge_hw_status swstatus;
	struct vxge_vpath *vpath = NULL;

	struct vxgedev *vdev = (struct vxgedev *)netdev_priv(dev);
	struct __vxge_hw_device  *hldev = vdev->devh;
	struct vxge_hw_xmac_stats *xmac_stats;
	struct vxge_hw_device_stats_sw_info *sw_stats;
	struct vxge_hw_device_stats_hw_info *hw_stats;

	u64 *ptr = tmp_stats;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24))
	count = vxge_ethtool_get_stats_count(dev);
#else
	count = vxge_ethtool_get_sset_count(dev, ETH_SS_STATS);
#endif
	memset(tmp_stats, 0, count * sizeof(u64));

	xmac_stats = kzalloc(sizeof(struct vxge_hw_xmac_stats), GFP_KERNEL);
	if (xmac_stats == NULL) {
		vxge_debug_init(VXGE_ERR,
			"%s : %d Memory Allocation failed for xmac_stats",
				 __func__, __LINE__);
		return;
	}

	sw_stats = kzalloc(sizeof(struct vxge_hw_device_stats_sw_info),
				GFP_KERNEL);
	if (sw_stats == NULL) {
		kfree(xmac_stats);
		vxge_debug_init(VXGE_ERR,
			"%s : %d Memory Allocation failed for sw_stats",
			__func__, __LINE__);
		return;
	}

	hw_stats = kzalloc(sizeof(struct vxge_hw_device_stats_hw_info),
				GFP_KERNEL);
	if (hw_stats == NULL) {
		kfree(xmac_stats);
		kfree(sw_stats);
		vxge_debug_init(VXGE_ERR,
			"%s : %d Memory Allocation failed for hw_stats",
			__func__, __LINE__);
		return;
	}

	*ptr++ = 0;
	status = vxge_hw_device_xmac_stats_get(hldev, xmac_stats);
	if (status != VXGE_HW_OK) {
		if (status != VXGE_HW_ERR_PRIVILAGED_OPEARATION) {
			vxge_debug_init(VXGE_ERR,
				"%s : %d Failure in getting xmac stats",
				__func__, __LINE__);
		}
	}
	swstatus = vxge_hw_driver_stats_get(hldev, sw_stats);
	if (swstatus != VXGE_HW_OK) {
		vxge_debug_init(VXGE_ERR,
			"%s : %d Failure in getting sw stats",
			__func__, __LINE__);
	}
	if (vxge_hw_device_hw_stats_enable(hldev) != VXGE_HW_OK) {
		vxge_debug_init(VXGE_ERR,
				"%s : %d hw_stats_get error\n",
				__func__, __LINE__);
	} else {
		status = vxge_hw_device_stats_get(hldev, hw_stats);
		if (status != VXGE_HW_OK) {
			vxge_debug_init(VXGE_ERR,
				"%s : %d hw_stats_get error",
				__func__, __LINE__);
		}
	}

	for (k = 0; k < vdev->no_of_vpath; k++) {
		struct vxge_hw_vpath_stats_hw_info *vpath_info;

		vpath = &vdev->vpaths[k];
		j = vpath->device_id;
		vpath_info = hw_stats->vpath_info[j];
		if (!vpath_info) {
			memset(ptr, 0, (VXGE_HW_VPATH_TX_STATS_LEN +
				VXGE_HW_VPATH_RX_STATS_LEN) * sizeof(u64));
			ptr += (VXGE_HW_VPATH_TX_STATS_LEN +
				VXGE_HW_VPATH_RX_STATS_LEN);
			continue;
		}

		*ptr++ = vpath_info->tx_stats.tx_ttl_eth_frms;
		*ptr++ = vpath_info->tx_stats.tx_ttl_eth_octets;
		*ptr++ = vpath_info->tx_stats.tx_data_octets;
		*ptr++ = vpath_info->tx_stats.tx_mcast_frms;
		*ptr++ = vpath_info->tx_stats.tx_bcast_frms;
		*ptr++ = vpath_info->tx_stats.tx_ucast_frms;
		*ptr++ = vpath_info->tx_stats.tx_tagged_frms;
		*ptr++ = vpath_info->tx_stats.tx_vld_ip;
		*ptr++ = vpath_info->tx_stats.tx_vld_ip_octets;
		*ptr++ = vpath_info->tx_stats.tx_icmp;
		*ptr++ = vpath_info->tx_stats.tx_tcp;
		*ptr++ = vpath_info->tx_stats.tx_rst_tcp;
		*ptr++ = vpath_info->tx_stats.tx_udp;
		*ptr++ = vpath_info->tx_stats.tx_unknown_protocol;
		*ptr++ = vpath_info->tx_stats.tx_lost_ip;
		*ptr++ = vpath_info->tx_stats.tx_parse_error;
		*ptr++ = vpath_info->tx_stats.tx_tcp_offload;
		*ptr++ = vpath_info->tx_stats.tx_retx_tcp_offload;
		*ptr++ = vpath_info->tx_stats.tx_lost_ip_offload;
		*ptr++ = vpath_info->rx_stats.rx_ttl_eth_frms;
		*ptr++ = vpath_info->rx_stats.rx_vld_frms;
		*ptr++ = vpath_info->rx_stats.rx_offload_frms;
		*ptr++ = vpath_info->rx_stats.rx_ttl_eth_octets;
		*ptr++ = vpath_info->rx_stats.rx_data_octets;
		*ptr++ = vpath_info->rx_stats.rx_offload_octets;
		*ptr++ = vpath_info->rx_stats.rx_vld_mcast_frms;
		*ptr++ = vpath_info->rx_stats.rx_vld_bcast_frms;
		*ptr++ = vpath_info->rx_stats.rx_accepted_ucast_frms;
		*ptr++ = vpath_info->rx_stats.rx_accepted_nucast_frms;
		*ptr++ = vpath_info->rx_stats.rx_tagged_frms;
		*ptr++ = vpath_info->rx_stats.rx_long_frms;
		*ptr++ = vpath_info->rx_stats.rx_usized_frms;
		*ptr++ = vpath_info->rx_stats.rx_osized_frms;
		*ptr++ = vpath_info->rx_stats.rx_frag_frms;
		*ptr++ = vpath_info->rx_stats.rx_jabber_frms;
		*ptr++ = vpath_info->rx_stats.rx_ttl_64_frms;
		*ptr++ = vpath_info->rx_stats.rx_ttl_65_127_frms;
		*ptr++ = vpath_info->rx_stats.rx_ttl_128_255_frms;
		*ptr++ = vpath_info->rx_stats.rx_ttl_256_511_frms;
		*ptr++ = vpath_info->rx_stats.rx_ttl_512_1023_frms;
		*ptr++ = vpath_info->rx_stats.rx_ttl_1024_1518_frms;
		*ptr++ = vpath_info->rx_stats.rx_ttl_1519_4095_frms;
		*ptr++ = vpath_info->rx_stats.rx_ttl_4096_8191_frms;
		*ptr++ = vpath_info->rx_stats.rx_ttl_8192_max_frms;
		*ptr++ = vpath_info->rx_stats.rx_ttl_gt_max_frms;
		*ptr++ = vpath_info->rx_stats.rx_ip;
		*ptr++ = vpath_info->rx_stats.rx_accepted_ip;
		*ptr++ = vpath_info->rx_stats.rx_ip_octets;
		*ptr++ = vpath_info->rx_stats.rx_err_ip;
		*ptr++ = vpath_info->rx_stats.rx_icmp;
		*ptr++ = vpath_info->rx_stats.rx_tcp;
		*ptr++ = vpath_info->rx_stats.rx_udp;
		*ptr++ = vpath_info->rx_stats.rx_err_tcp;
		*ptr++ = vpath_info->rx_stats.rx_lost_frms;
		*ptr++ = vpath_info->rx_stats.rx_lost_ip;
		*ptr++ = vpath_info->rx_stats.rx_lost_ip_offload;
		*ptr++ = vpath_info->rx_stats.rx_various_discard;
		*ptr++ = vpath_info->rx_stats.rx_sleep_discard;
		*ptr++ = vpath_info->rx_stats.rx_red_discard;
		*ptr++ = vpath_info->rx_stats.rx_queue_full_discard;
		*ptr++ = vpath_info->rx_stats.rx_mpa_ok_frms;
	}
	*ptr++ = 0;
	for (k = 0; k < VXGE_HW_MAC_MAX_WIRE_PORTS; k++) {
		*ptr++ = xmac_stats->aggr_stats[k].tx_frms;
		*ptr++ = xmac_stats->aggr_stats[k].tx_data_octets;
		*ptr++ = xmac_stats->aggr_stats[k].tx_mcast_frms;
		*ptr++ = xmac_stats->aggr_stats[k].tx_bcast_frms;
		*ptr++ = xmac_stats->aggr_stats[k].tx_discarded_frms;
		*ptr++ = xmac_stats->aggr_stats[k].tx_errored_frms;
		*ptr++ = xmac_stats->aggr_stats[k].rx_frms;
		*ptr++ = xmac_stats->aggr_stats[k].rx_data_octets;
		*ptr++ = xmac_stats->aggr_stats[k].rx_mcast_frms;
		*ptr++ = xmac_stats->aggr_stats[k].rx_bcast_frms;
		*ptr++ = xmac_stats->aggr_stats[k].rx_discarded_frms;
		*ptr++ = xmac_stats->aggr_stats[k].rx_errored_frms;
		*ptr++ = xmac_stats->aggr_stats[k].rx_unknown_slow_proto_frms;
	}
	*ptr++ = 0;
	for (k = 0; k < VXGE_HW_MAC_MAX_WIRE_PORTS; k++) {
		*ptr++ = xmac_stats->port_stats[k].tx_ttl_frms;
		*ptr++ = xmac_stats->port_stats[k].tx_ttl_octets;
		*ptr++ = xmac_stats->port_stats[k].tx_data_octets;
		*ptr++ = xmac_stats->port_stats[k].tx_mcast_frms;
		*ptr++ = xmac_stats->port_stats[k].tx_bcast_frms;
		*ptr++ = xmac_stats->port_stats[k].tx_ucast_frms;
		*ptr++ = xmac_stats->port_stats[k].tx_tagged_frms;
		*ptr++ = xmac_stats->port_stats[k].tx_vld_ip;
		*ptr++ = xmac_stats->port_stats[k].tx_vld_ip_octets;
		*ptr++ = xmac_stats->port_stats[k].tx_icmp;
		*ptr++ = xmac_stats->port_stats[k].tx_tcp;
		*ptr++ = xmac_stats->port_stats[k].tx_rst_tcp;
		*ptr++ = xmac_stats->port_stats[k].tx_udp;
		*ptr++ = xmac_stats->port_stats[k].tx_parse_error;
		*ptr++ = xmac_stats->port_stats[k].tx_unknown_protocol;
		*ptr++ = xmac_stats->port_stats[k].tx_pause_ctrl_frms;
		*ptr++ = xmac_stats->port_stats[k].tx_marker_pdu_frms;
		*ptr++ = xmac_stats->port_stats[k].tx_lacpdu_frms;
		*ptr++ = xmac_stats->port_stats[k].tx_drop_ip;
		*ptr++ = xmac_stats->port_stats[k].tx_marker_resp_pdu_frms;
		*ptr++ = xmac_stats->port_stats[k].tx_xgmii_char2_match;
		*ptr++ = xmac_stats->port_stats[k].tx_xgmii_char1_match;
		*ptr++ = xmac_stats->port_stats[k].tx_xgmii_column2_match;
		*ptr++ = xmac_stats->port_stats[k].tx_xgmii_column1_match;
		*ptr++ = xmac_stats->port_stats[k].tx_any_err_frms;
		*ptr++ = xmac_stats->port_stats[k].tx_drop_frms;
		*ptr++ = xmac_stats->port_stats[k].rx_ttl_frms;
		*ptr++ = xmac_stats->port_stats[k].rx_vld_frms;
		*ptr++ = xmac_stats->port_stats[k].rx_offload_frms;
		*ptr++ = xmac_stats->port_stats[k].rx_ttl_octets;
		*ptr++ = xmac_stats->port_stats[k].rx_data_octets;
		*ptr++ = xmac_stats->port_stats[k].rx_offload_octets;
		*ptr++ = xmac_stats->port_stats[k].rx_vld_mcast_frms;
		*ptr++ = xmac_stats->port_stats[k].rx_vld_bcast_frms;
		*ptr++ = xmac_stats->port_stats[k].rx_accepted_ucast_frms;
		*ptr++ = xmac_stats->port_stats[k].rx_accepted_nucast_frms;
		*ptr++ = xmac_stats->port_stats[k].rx_tagged_frms;
		*ptr++ = xmac_stats->port_stats[k].rx_long_frms;
		*ptr++ = xmac_stats->port_stats[k].rx_usized_frms;
		*ptr++ = xmac_stats->port_stats[k].rx_osized_frms;
		*ptr++ = xmac_stats->port_stats[k].rx_frag_frms;
		*ptr++ = xmac_stats->port_stats[k].rx_jabber_frms;
		*ptr++ = xmac_stats->port_stats[k].rx_ttl_64_frms;
		*ptr++ = xmac_stats->port_stats[k].rx_ttl_65_127_frms;
		*ptr++ = xmac_stats->port_stats[k].rx_ttl_128_255_frms;
		*ptr++ = xmac_stats->port_stats[k].rx_ttl_256_511_frms;
		*ptr++ = xmac_stats->port_stats[k].rx_ttl_512_1023_frms;
		*ptr++ = xmac_stats->port_stats[k].rx_ttl_1024_1518_frms;
		*ptr++ = xmac_stats->port_stats[k].rx_ttl_1519_4095_frms;
		*ptr++ = xmac_stats->port_stats[k].rx_ttl_4096_8191_frms;
		*ptr++ = xmac_stats->port_stats[k].rx_ttl_8192_max_frms;
		*ptr++ = xmac_stats->port_stats[k].rx_ttl_gt_max_frms;
		*ptr++ = xmac_stats->port_stats[k].rx_ip;
		*ptr++ = xmac_stats->port_stats[k].rx_accepted_ip;
		*ptr++ = xmac_stats->port_stats[k].rx_ip_octets;
		*ptr++ = xmac_stats->port_stats[k].rx_err_ip;
		*ptr++ = xmac_stats->port_stats[k].rx_icmp;
		*ptr++ = xmac_stats->port_stats[k].rx_tcp;
		*ptr++ = xmac_stats->port_stats[k].rx_udp;
		*ptr++ = xmac_stats->port_stats[k].rx_err_tcp;
		*ptr++ = xmac_stats->port_stats[k].rx_pause_count;
		*ptr++ = xmac_stats->port_stats[k].rx_pause_ctrl_frms;
		*ptr++ = xmac_stats->port_stats[k].rx_unsup_ctrl_frms;
		*ptr++ = xmac_stats->port_stats[k].rx_fcs_err_frms;
		*ptr++ = xmac_stats->port_stats[k].rx_in_rng_len_err_frms;
		*ptr++ = xmac_stats->port_stats[k].rx_out_rng_len_err_frms;
		*ptr++ = xmac_stats->port_stats[k].rx_drop_frms;
		*ptr++ = xmac_stats->port_stats[k].rx_discarded_frms;
		*ptr++ = xmac_stats->port_stats[k].rx_drop_ip;
		*ptr++ = xmac_stats->port_stats[k].rx_drop_udp;
		*ptr++ = xmac_stats->port_stats[k].rx_marker_pdu_frms;
		*ptr++ = xmac_stats->port_stats[k].rx_lacpdu_frms;
		*ptr++ = xmac_stats->port_stats[k].rx_unknown_pdu_frms;
		*ptr++ = xmac_stats->port_stats[k].rx_marker_resp_pdu_frms;
		*ptr++ = xmac_stats->port_stats[k].rx_fcs_discard;
		*ptr++ = xmac_stats->port_stats[k].rx_illegal_pdu_frms;
		*ptr++ = xmac_stats->port_stats[k].rx_switch_discard;
		*ptr++ = xmac_stats->port_stats[k].rx_len_discard;
		*ptr++ = xmac_stats->port_stats[k].rx_rpa_discard;
		*ptr++ = xmac_stats->port_stats[k].rx_l2_mgmt_discard;
		*ptr++ = xmac_stats->port_stats[k].rx_rts_discard;
		*ptr++ = xmac_stats->port_stats[k].rx_trash_discard;
		*ptr++ = xmac_stats->port_stats[k].rx_buff_full_discard;
		*ptr++ = xmac_stats->port_stats[k].rx_red_discard;
		*ptr++ = xmac_stats->port_stats[k].rx_xgmii_ctrl_err_cnt;
		*ptr++ = xmac_stats->port_stats[k].rx_xgmii_data_err_cnt;
		*ptr++ = xmac_stats->port_stats[k].rx_xgmii_char1_match;
		*ptr++ = xmac_stats->port_stats[k].rx_xgmii_err_sym;
		*ptr++ = xmac_stats->port_stats[k].rx_xgmii_column1_match;
		*ptr++ = xmac_stats->port_stats[k].rx_xgmii_char2_match;
		*ptr++ = xmac_stats->port_stats[k].rx_local_fault;
		*ptr++ = xmac_stats->port_stats[k].rx_xgmii_column2_match;
		*ptr++ = xmac_stats->port_stats[k].rx_jettison;
		*ptr++ = xmac_stats->port_stats[k].rx_remote_fault;
	}

	*ptr++ = 0;
	for (k = 0; k < vdev->no_of_vpath; k++) {
		struct vxge_hw_vpath_stats_sw_info *vpath_info;

		vpath = &vdev->vpaths[k];
		j = vpath->device_id;
		vpath_info = (struct vxge_hw_vpath_stats_sw_info *)
				&sw_stats->vpath_info[j];
		*ptr++ = vpath_info->soft_reset_cnt;
		*ptr++ = vpath_info->error_stats.unknown_alarms;
		*ptr++ = vpath_info->error_stats.network_sustained_fault;
		*ptr++ = vpath_info->error_stats.network_sustained_ok;
		*ptr++ = vpath_info->error_stats.kdfcctl_fifo0_overwrite;
		*ptr++ = vpath_info->error_stats.kdfcctl_fifo0_poison;
		*ptr++ = vpath_info->error_stats.kdfcctl_fifo0_dma_error;
		*ptr++ = vpath_info->error_stats.dblgen_fifo0_overflow;
		*ptr++ = vpath_info->error_stats.statsb_pif_chain_error;
		*ptr++ = vpath_info->error_stats.statsb_drop_timeout;
		*ptr++ = vpath_info->error_stats.target_illegal_access;
		*ptr++ = vpath_info->error_stats.ini_serr_det;
		*ptr++ = vpath_info->error_stats.prc_ring_bumps;
		*ptr++ = vpath_info->error_stats.prc_rxdcm_sc_err;
		*ptr++ = vpath_info->error_stats.prc_rxdcm_sc_abort;
		*ptr++ = vpath_info->error_stats.prc_quanta_size_err;
		*ptr++ = vpath_info->ring_stats.common_stats.full_cnt;
		*ptr++ = vpath_info->ring_stats.common_stats.usage_cnt;
		*ptr++ = vpath_info->ring_stats.common_stats.usage_max;
		*ptr++ = vpath_info->ring_stats.common_stats.
					reserve_free_swaps_cnt;
		*ptr++ = vpath_info->ring_stats.common_stats.total_compl_cnt;
		for (j = 0; j < VXGE_HW_DTR_MAX_T_CODE; j++)
			*ptr++ = vpath_info->ring_stats.rxd_t_code_err_cnt[j];

		if ((vdev->config.lro_enable) &&
			vdev->config.lro_enable != VXGE_HW_GRO_ENABLE) {
			*ptr++ = vpath_info->ring_stats.lro_clubbed_frms_cnt;
			*ptr++ = vpath_info->ring_stats.lro_sending_both;
			*ptr++ = vpath_info->ring_stats.lro_outof_sequence_pkts;
			*ptr++ = vpath_info->ring_stats.lro_flush_max_pkts;
			*ptr++ = vpath_info->ring_stats.lro_avg_agr_pkts;
			*ptr++ = vpath_info->ring_stats.lro_max_pkts_aggr;
		}

		*ptr++ = vpath_info->fifo_stats.common_stats.full_cnt;
		*ptr++ = vpath_info->fifo_stats.common_stats.usage_cnt;
		*ptr++ = vpath_info->fifo_stats.common_stats.usage_max;
		*ptr++ = vpath_info->fifo_stats.common_stats.
						reserve_free_swaps_cnt;
		*ptr++ = vpath_info->fifo_stats.common_stats.total_compl_cnt;
		*ptr++ = vpath_info->fifo_stats.total_posts;
		*ptr++ = vpath_info->fifo_stats.total_buffers;
		for (j = 0; j < VXGE_HW_DTR_MAX_T_CODE; j++)
			*ptr++ = vpath_info->fifo_stats.txd_t_code_err_cnt[j];
	}

	*ptr++ = 0;
	*ptr++ = vdev->stats.vpaths_open;
	*ptr++ = vdev->stats.vpath_open_fail;
	*ptr++ = vdev->stats.link_up;
	*ptr++ = vdev->stats.link_down;

	for (k = 0; k < vdev->no_of_vpath; k++) {
		*ptr += vdev->vpaths[k].fifo.stats.tx_frms;
		*(ptr + 1) += vdev->vpaths[k].fifo.stats.tx_errors;
		*(ptr + 2) += vdev->vpaths[k].fifo.stats.tx_bytes;
		*(ptr + 3) += vdev->vpaths[k].fifo.stats.txd_not_free;
		*(ptr + 4) += vdev->vpaths[k].fifo.stats.txd_out_of_desc;
		*(ptr + 5) += vdev->vpaths[k].ring.stats.rx_frms;
		*(ptr + 6) += vdev->vpaths[k].ring.stats.rx_errors;
		*(ptr + 7) += vdev->vpaths[k].ring.stats.rx_bytes;
		*(ptr + 8) += vdev->vpaths[k].ring.stats.rx_mcast;
		*(ptr + 9) += vdev->vpaths[k].fifo.stats.pci_map_fail +
				vdev->vpaths[k].ring.stats.pci_map_fail;
		*(ptr + 10) += vdev->vpaths[k].ring.stats.skb_alloc_fail;
	}

	ptr += 12;

	kfree(xmac_stats);
	kfree(sw_stats);
	kfree(hw_stats);
}

#ifdef VXGE_SELF_TEST

static int vxge_eeprom_test(struct vxgedev *vdev, uint64_t *data)
{
	int status = 0;

	status = vxge_perform_self_test(vdev, VXGE_EEPROM_ACCESS_TEST);

	*data = status;
	return status;
}

static int vxge_mdio_port0_test(struct vxgedev *vdev, uint64_t *data)
{
	int status = 0;

	status = vxge_perform_self_test(vdev, VXGE_MDIO_PORT0_TEST);

	*data = status;
	return status;
}

static int vxge_mdio_port1_test(struct vxgedev *vdev, uint64_t *data)
{
	int status = 0;

	status = vxge_perform_self_test(vdev, VXGE_MDIO_PORT1_TEST);

	*data = status;
	return status;
}

static int vxge_flash_test(struct vxgedev *vdev, uint64_t *data)
{
	int status = 0;

	status = vxge_perform_self_test(vdev, VXGE_FLASH_TEST);

	*data = status;
	return status;
}

static int vxge_bist_test(struct vxgedev *vdev, uint64_t *data)
{
	int status = 0;

	status = vxge_perform_self_test(vdev, VXGE_FRAME_BUFFER_TEST);

	*data = status;
	return status;
}

static int vxge_context_test(struct vxgedev *vdev, uint64_t *data)
{
	int status = 0;

	status = vxge_perform_self_test(vdev, VXGE_CONTEXT_MEM_TEST);

	*data = status;
	return status;
}

/**
 * vxge_ethtool_test - Conducts 6 tests to determine the health of card.
 *  @dev : pointer to netdev structure.
 *  @ethtest : pointer to a ethtool command specific structure that will be
 *  returned to the user.
 *  @data : variable that returns the result of each of the test conducted
 *  by the driver.
 * Description:
 *  This function conducts 6 offline tests to determine the health of the
 *  card.
 * Return value:
 *  void
 */

static void vxge_ethtool_test(struct net_device *dev,
			struct ethtool_test *ethtest,
			uint64_t *data)
{
	struct vxgedev *vdev = (struct vxgedev *)netdev_priv(dev);
	int orig_state = netif_running(dev);

	if (ethtest->flags == ETH_TEST_FL_OFFLINE) {

		/* Offline Tests. */
		if (orig_state)
			vxge_close(dev);

		msleep (5);
		if (vxge_eeprom_test(vdev, &data[0]))
			ethtest->flags |= ETH_TEST_FL_FAILED;

		if (vxge_mdio_port0_test(vdev, &data[1]))
			ethtest->flags |= ETH_TEST_FL_FAILED;

		if (vxge_mdio_port1_test(vdev, &data[2]))
			ethtest->flags |= ETH_TEST_FL_FAILED;

		if (vxge_flash_test(vdev, &data[3]))
			ethtest->flags |= ETH_TEST_FL_FAILED;

		if (vxge_bist_test(vdev, &data[4]))
			ethtest->flags |= ETH_TEST_FL_FAILED;

		if (vxge_context_test(vdev, &data[5]))
			ethtest->flags |= ETH_TEST_FL_FAILED;

		if (orig_state)
			vxge_open(dev);

	} else {
		/* Online Tests */
	}
}

#endif
static void vxge_ethtool_get_strings(struct net_device *dev,
			      u32 stringset, u8 *data)
{
	int stat_size = 0;
	int i, j;
	struct vxgedev *vdev = (struct vxgedev *)netdev_priv(dev);

	switch (stringset) {
#ifdef VXGE_SELF_TEST
	case ETH_SS_TEST:
		memcpy(data, vxge_gstrings, VXGE_STRINGS_LEN);
		break;
#endif

	case ETH_SS_STATS:
		vxge_add_string("VPATH STATISTICS%s\t\t\t",
			&stat_size, data, "");
		for (i = 0; i < vdev->no_of_vpath; i++) {
			vxge_add_string("tx_ttl_eth_frms_%d\t\t\t",
					&stat_size, data, i);
			vxge_add_string("tx_ttl_eth_octects_%d\t\t",
					&stat_size, data, i);
			vxge_add_string("tx_data_octects_%d\t\t\t",
					&stat_size, data, i);
			vxge_add_string("tx_mcast_frms_%d\t\t\t",
					&stat_size, data, i);
			vxge_add_string("tx_bcast_frms_%d\t\t\t",
					&stat_size, data, i);
			vxge_add_string("tx_ucast_frms_%d\t\t\t",
					&stat_size, data, i);
			vxge_add_string("tx_tagged_frms_%d\t\t\t",
					&stat_size, data, i);
			vxge_add_string("tx_vld_ip_%d\t\t\t",
					&stat_size, data, i);
			vxge_add_string("tx_vld_ip_octects_%d\t\t",
					&stat_size, data, i);
			vxge_add_string("tx_icmp_%d\t\t\t\t",
					&stat_size, data, i);
			vxge_add_string("tx_tcp_%d\t\t\t\t",
					&stat_size, data, i);
			vxge_add_string("tx_rst_tcp_%d\t\t\t",
					&stat_size, data, i);
			vxge_add_string("tx_udp_%d\t\t\t\t",
					&stat_size, data, i);
			vxge_add_string("tx_unknown_proto_%d\t\t\t",
					&stat_size, data, i);
			vxge_add_string("tx_lost_ip_%d\t\t\t",
					&stat_size, data, i);
			vxge_add_string("tx_parse_error_%d\t\t\t",
					&stat_size, data, i);
			vxge_add_string("tx_tcp_offload_%d\t\t\t",
					&stat_size, data, i);
			vxge_add_string("tx_retx_tcp_offload_%d\t\t",
					&stat_size, data, i);
			vxge_add_string("tx_lost_ip_offload_%d\t\t",
					&stat_size, data, i);
			vxge_add_string("rx_ttl_eth_frms_%d\t\t\t",
					&stat_size, data, i);
			vxge_add_string("rx_vld_frms_%d\t\t\t",
					&stat_size, data, i);
			vxge_add_string("rx_offload_frms_%d\t\t\t",
					&stat_size, data, i);
			vxge_add_string("rx_ttl_eth_octects_%d\t\t",
					&stat_size, data, i);
			vxge_add_string("rx_data_octects_%d\t\t\t",
					&stat_size, data, i);
			vxge_add_string("rx_offload_octects_%d\t\t",
					&stat_size, data, i);
			vxge_add_string("rx_vld_mcast_frms_%d\t\t",
					&stat_size, data, i);
			vxge_add_string("rx_vld_bcast_frms_%d\t\t",
					&stat_size, data, i);
			vxge_add_string("rx_accepted_ucast_frms_%d\t\t",
					&stat_size, data, i);
			vxge_add_string("rx_accepted_nucast_frms_%d\t\t",
					&stat_size, data, i);
			vxge_add_string("rx_tagged_frms_%d\t\t\t",
					&stat_size, data, i);
			vxge_add_string("rx_long_frms_%d\t\t\t",
					&stat_size, data, i);
			vxge_add_string("rx_usized_frms_%d\t\t\t",
					&stat_size, data, i);
			vxge_add_string("rx_osized_frms_%d\t\t\t",
					&stat_size, data, i);
			vxge_add_string("rx_frag_frms_%d\t\t\t",
					&stat_size, data, i);
			vxge_add_string("rx_jabber_frms_%d\t\t\t",
					&stat_size, data, i);
			vxge_add_string("rx_ttl_64_frms_%d\t\t\t",
					&stat_size, data, i);
			vxge_add_string("rx_ttl_65_127_frms_%d\t\t",
					&stat_size, data, i);
			vxge_add_string("rx_ttl_128_255_frms_%d\t\t",
					&stat_size, data, i);
			vxge_add_string("rx_ttl_256_511_frms_%d\t\t",
					&stat_size, data, i);
			vxge_add_string("rx_ttl_512_1023_frms_%d\t\t",
					&stat_size, data, i);
			vxge_add_string("rx_ttl_1024_1518_frms_%d\t\t",
					&stat_size, data, i);
			vxge_add_string("rx_ttl_1519_4095_frms_%d\t\t",
					&stat_size, data, i);
			vxge_add_string("rx_ttl_4096_8191_frms_%d\t\t",
					&stat_size, data, i);
			vxge_add_string("rx_ttl_8192_max_frms_%d\t\t",
					&stat_size, data, i);
			vxge_add_string("rx_ttl_gt_max_frms_%d\t\t",
					&stat_size, data, i);
			vxge_add_string("rx_ip%d\t\t\t\t",
					&stat_size, data, i);
			vxge_add_string("rx_accepted_ip_%d\t\t\t",
					&stat_size, data, i);
			vxge_add_string("rx_ip_octects_%d\t\t\t",
					&stat_size, data, i);
			vxge_add_string("rx_err_ip_%d\t\t\t",
					&stat_size, data, i);
			vxge_add_string("rx_icmp_%d\t\t\t\t",
					&stat_size, data, i);
			vxge_add_string("rx_tcp_%d\t\t\t\t",
					&stat_size, data, i);
			vxge_add_string("rx_udp_%d\t\t\t\t",
					&stat_size, data, i);
			vxge_add_string("rx_err_tcp_%d\t\t\t",
					&stat_size, data, i);
			vxge_add_string("rx_lost_frms_%d\t\t\t",
					&stat_size, data, i);
			vxge_add_string("rx_lost_ip_%d\t\t\t",
					&stat_size, data, i);
			vxge_add_string("rx_lost_ip_offload_%d\t\t",
					&stat_size, data, i);
			vxge_add_string("rx_various_discard_%d\t\t",
					&stat_size, data, i);
			vxge_add_string("rx_sleep_discard_%d\t\t\t",
					&stat_size, data, i);
			vxge_add_string("rx_red_discard_%d\t\t\t",
					&stat_size, data, i);
			vxge_add_string("rx_queue_full_discard_%d\t\t",
					&stat_size, data, i);
			vxge_add_string("rx_mpa_ok_frms_%d\t\t\t",
					&stat_size, data, i);
		}

		vxge_add_string("\nAGGR STATISTICS%s\t\t\t\t",
			&stat_size, data, "");
		for (i = 0; i < VXGE_HW_MAC_MAX_WIRE_PORTS; i++) {
			vxge_add_string("tx_frms_%d\t\t\t\t",
				&stat_size, data, i);
			vxge_add_string("tx_data_octects_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("tx_mcast_frms_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("tx_bcast_frms_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("tx_discarded_frms_%d\t\t",
				&stat_size, data, i);
			vxge_add_string("tx_errored_frms_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_frms_%d\t\t\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_data_octects_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_mcast_frms_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_bcast_frms_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_discarded_frms_%d\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_errored_frms_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_unknown_slow_proto_frms_%d\t",
				&stat_size, data, i);
		}

		vxge_add_string("\nPORT STATISTICS%s\t\t\t\t",
			&stat_size, data, "");
		for (i = 0; i < VXGE_HW_MAC_MAX_WIRE_PORTS; i++) {
			vxge_add_string("tx_ttl_frms_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("tx_ttl_octects_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("tx_data_octects_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("tx_mcast_frms_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("tx_bcast_frms_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("tx_ucast_frms_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("tx_tagged_frms_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("tx_vld_ip_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("tx_vld_ip_octects_%d\t\t",
				&stat_size, data, i);
			vxge_add_string("tx_icmp_%d\t\t\t\t",
				&stat_size, data, i);
			vxge_add_string("tx_tcp_%d\t\t\t\t",
				&stat_size, data, i);
			vxge_add_string("tx_rst_tcp_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("tx_udp_%d\t\t\t\t",
				&stat_size, data, i);
			vxge_add_string("tx_parse_error_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("tx_unknown_protocol_%d\t\t",
				&stat_size, data, i);
			vxge_add_string("tx_pause_ctrl_frms_%d\t\t",
				&stat_size, data, i);
			vxge_add_string("tx_marker_pdu_frms_%d\t\t",
				&stat_size, data, i);
			vxge_add_string("tx_lacpdu_frms_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("tx_drop_ip_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("tx_marker_resp_pdu_frms_%d\t\t",
				&stat_size, data, i);
			vxge_add_string("tx_xgmii_char2_match_%d\t\t",
				&stat_size, data, i);
			vxge_add_string("tx_xgmii_char1_match_%d\t\t",
				&stat_size, data, i);
			vxge_add_string("tx_xgmii_column2_match_%d\t\t",
				&stat_size, data, i);
			vxge_add_string("tx_xgmii_column1_match_%d\t\t",
				&stat_size, data, i);
			vxge_add_string("tx_any_err_frms_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("tx_drop_frms_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_ttl_frms_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_vld_frms_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_offload_frms_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_ttl_octects_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_data_octects_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_offload_octects_%d\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_vld_mcast_frms_%d\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_vld_bcast_frms_%d\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_accepted_ucast_frms_%d\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_accepted_nucast_frms_%d\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_tagged_frms_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_long_frms_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_usized_frms_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_osized_frms_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_frag_frms_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_jabber_frms_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_ttl_64_frms_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_ttl_65_127_frms_%d\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_ttl_128_255_frms_%d\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_ttl_256_511_frms_%d\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_ttl_512_1023_frms_%d\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_ttl_1024_1518_frms_%d\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_ttl_1519_4095_frms_%d\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_ttl_4096_8191_frms_%d\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_ttl_8192_max_frms_%d\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_ttl_gt_max_frms_%d\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_ip_%d\t\t\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_accepted_ip_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_ip_octets_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_err_ip_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_icmp_%d\t\t\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_tcp_%d\t\t\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_udp_%d\t\t\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_err_tcp_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_pause_count_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_pause_ctrl_frms_%d\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_unsup_ctrl_frms_%d\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_fcs_err_frms_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_in_rng_len_err_frms_%d\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_out_rng_len_err_frms_%d\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_drop_frms_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_discard_frms_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_drop_ip_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_drop_udp_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_marker_pdu_frms_%d\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_lacpdu_frms_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_unknown_pdu_frms_%d\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_marker_resp_pdu_frms_%d\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_fcs_discard_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_illegal_pdu_frms_%d\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_switch_discard_%d\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_len_discard_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_rpa_discard_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_l2_mgmt_discard_%d\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_rts_discard_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_trash_discard_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_buff_full_discard_%d\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_red_discard_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_xgmii_ctrl_err_cnt_%d\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_xgmii_data_err_cnt_%d\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_xgmii_char1_match_%d\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_xgmii_err_sym_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_xgmii_column1_match_%d\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_xgmii_char2_match_%d\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_local_fault_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_xgmii_column2_match_%d\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_jettison_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("rx_remote_fault_%d\t\t\t",
				&stat_size, data, i);
		}

		vxge_add_string("\n SOFTWARE STATISTICS%s\t\t\t",
			&stat_size, data, "");
		for (i = 0; i < vdev->no_of_vpath; i++) {
			vxge_add_string("soft_reset_cnt_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("unknown_alarms_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("network_sustained_fault_%d\t\t",
				&stat_size, data, i);
			vxge_add_string("network_sustained_ok_%d\t\t",
				&stat_size, data, i);
			vxge_add_string("kdfcctl_fifo0_overwrite_%d\t\t",
				&stat_size, data, i);
			vxge_add_string("kdfcctl_fifo0_poison_%d\t\t",
				&stat_size, data, i);
			vxge_add_string("kdfcctl_fifo0_dma_error_%d\t\t",
				&stat_size, data, i);
			vxge_add_string("dblgen_fifo0_overflow_%d\t\t",
				&stat_size, data, i);
			vxge_add_string("statsb_pif_chain_error_%d\t\t",
				&stat_size, data, i);
			vxge_add_string("statsb_drop_timeout_%d\t\t",
				&stat_size, data, i);
			vxge_add_string("target_illegal_access_%d\t\t",
				&stat_size, data, i);
			vxge_add_string("ini_serr_det_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("prc_ring_bumps_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("prc_rxdcm_sc_err_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("prc_rxdcm_sc_abort_%d\t\t",
				&stat_size, data, i);
			vxge_add_string("prc_quanta_size_err_%d\t\t",
				&stat_size, data, i);
			vxge_add_string("ring_full_cnt_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("ring_usage_cnt_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("ring_usage_max_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("ring_reserve_free_swaps_cnt_%d\t",
				&stat_size, data, i);
			vxge_add_string("ring_total_compl_cnt_%d\t\t",
				&stat_size, data, i);
			for (j = 0; j < VXGE_HW_DTR_MAX_T_CODE; j++)
				vxge_add_string("rxd_t_code_err_cnt%d_%d\t\t",
					&stat_size, data, j, i);

			if ((vdev->config.lro_enable) &&
				vdev->config.lro_enable != VXGE_HW_GRO_ENABLE) {
				vxge_add_string("lro_aggregated_pkts_%d\t\t",
					&stat_size, data, i);
				vxge_add_string("lro_flush_both_count_%d\t\t",
					&stat_size, data, i);
				vxge_add_string( "lro_out_of_sequence_pkts_%d\t\t",
					&stat_size, data, i);
				vxge_add_string("lro_flush_due_to_max_pkts_%d\t",
					&stat_size, data, i);
				vxge_add_string("lro_avg_aggr_pkts_%d\t\t",
					&stat_size, data, i);
				vxge_add_string("lro_max_pkts_aggr_%d\t\t",
					&stat_size, data, i);
			}

			vxge_add_string("fifo_full_cnt_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("fifo_usage_cnt_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("fifo_usage_max_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("fifo_reserve_free_swaps_cnt_%d\t",
				&stat_size, data, i);
			vxge_add_string("fifo_total_compl_cnt_%d\t\t",
				&stat_size, data, i);
			vxge_add_string("fifo_total_posts_%d\t\t\t",
				&stat_size, data, i);
			vxge_add_string("fifo_total_buffers_%d\t\t",
				&stat_size, data, i);
			for (j = 0; j < VXGE_HW_DTR_MAX_T_CODE; j++)
				vxge_add_string("txd_t_code_err_cnt%d_%d\t\t",
					&stat_size, data, j, i);
		}

		memcpy(data + stat_size, &ethtool_driver_stats_keys,
			sizeof(ethtool_driver_stats_keys));
		stat_size += sizeof(ethtool_driver_stats_keys);

	}
}

#ifdef NETIF_F_TSO
static int vxge_ethtool_op_set_tso(struct net_device *dev, u32 data)
{
	if (data) {
		dev->features |= NETIF_F_TSO;
#ifdef NETIF_F_TSO6
		dev->features |= NETIF_F_TSO6;
#endif
		}
	else {
		dev->features &= ~NETIF_F_TSO;
#ifdef NETIF_F_TSO6
		dev->features &= ~NETIF_F_TSO6;
#endif
	}

	return 0;
}
#endif

#ifndef SET_ETHTOOL_OPS
/*
 * vxge_ethtool - to support all ethtool features .
 * @dev: device pointer.
 * @ifr: An IOCTL specefic structure, that can contain a pointer to
 * a proprietary structure used to pass information to the driver.
 *
 * Function used to support all ethtool features except dumping Device stats
 * as it can be obtained from the util tool for now.
 *
 * 0 on success and an appropriate (-)ve integer as defined in errno.h
 * file on failure.
 */
int vxge_ethtool(struct net_device *dev, struct ifreq *rq)
{
	void *data = rq->ifr_data;
	u32 ecmd;
	struct vxgedev *vdev = (struct vxgedev *)netdev_priv(dev);

	if (get_user(ecmd, (u32 *)data))
		return -EFAULT;

	switch (ecmd) {
	case ETHTOOL_GSET:
		{
			struct ethtool_cmd info = { ETHTOOL_GSET };
			vxge_ethtool_gset(dev, &info);
			if (copy_to_user(data, &info, sizeof(info)))
				return -EFAULT;
			break;
		}
	case ETHTOOL_SSET:
		{
			struct ethtool_cmd info;

			if (copy_from_user(&info, data, sizeof(info)))
				return -EFAULT;
			if (vxge_ethtool_sset(dev, &info))
				return -EFAULT;
			break;
		}
	case ETHTOOL_GDRVINFO:
		{
			struct ethtool_drvinfo info = { ETHTOOL_GDRVINFO };

			vxge_ethtool_gdrvinfo(dev, &info);
			if (copy_to_user(data, &info, sizeof(info)))
				return -EFAULT;
			break;
		}
	case ETHTOOL_GLINK:
		{
			struct ethtool_value link = { ETHTOOL_GLINK };

			link.data = netif_carrier_ok(dev);
			if (copy_to_user(data, &link, sizeof(link)))
				return -EFAULT;
			break;
		}
	case ETHTOOL_PHYS_ID:
		{
			struct ethtool_value id;

			if (copy_from_user(&id, data, sizeof(id)))
				return -EFAULT;
			vxge_ethtool_idnic(dev, id.data);
			break;
		}
	case ETHTOOL_GPAUSEPARAM:
		{
			struct ethtool_pauseparam ep = { ETHTOOL_GPAUSEPARAM };
			int tx = 0, rx = 0;

			vxge_ethtool_getpause_data(dev, &ep);
			ep.tx_pause = tx;
			ep.rx_pause = rx;
			ep.autoneg = 0;
			if (copy_to_user(data, &ep, sizeof(ep)))
				return -EFAULT;
			break;

		}
	case ETHTOOL_SPAUSEPARAM:
		{
			struct ethtool_pauseparam ep;
			int tx = 0, rx = 0;

			if (copy_from_user(&ep, data, sizeof(ep)))
				return -EFAULT;
			tx = ep.tx_pause;
			rx = ep.rx_pause;
			vxge_ethtool_setpause_data(dev, &ep);
			break;
		}
	case ETHTOOL_GRXCSUM:
		{
			struct ethtool_value ev = { ETHTOOL_GRXCSUM };

			ev.data = vdev->rx_csum;
			if (copy_to_user(data, &ev, sizeof(ev)))
				return -EFAULT;
			break;
		}
	case ETHTOOL_GTXCSUM:
		{
			struct ethtool_value ev = { ETHTOOL_GTXCSUM };
			ev.data = (dev->features & NETIF_F_HW_CSUM);

			if (copy_to_user(data, &ev, sizeof(ev)))
				return -EFAULT;
			break;
		}
	case ETHTOOL_GSG:
		{
			struct ethtool_value ev = { ETHTOOL_GSG };
			ev.data = (dev->features & NETIF_F_SG);

			if (copy_to_user(data, &ev, sizeof(ev)))
				return -EFAULT;
			break;
		}
#ifdef NETIF_F_TSO
	case ETHTOOL_GTSO:
		{
			struct ethtool_value ev = { ETHTOOL_GTSO };
			ev.data = (dev->features & NETIF_F_TSO);

			if (copy_to_user(data, &ev, sizeof(ev)))
				return -EFAULT;
			break;
		}
#endif
	case ETHTOOL_STXCSUM:
		{
			struct ethtool_value ev;

			if (copy_from_user(&ev, data, sizeof(ev)))
				return -EFAULT;

			if (ev.data)
				dev->features |= NETIF_F_HW_CSUM;
			else
				dev->features &= ~NETIF_F_HW_CSUM;
			break;
		}
	case ETHTOOL_SRXCSUM:
		{
			struct ethtool_value ev;
			int i;

			if (copy_from_user(&ev, data, sizeof(ev)))
				return -EFAULT;

			if (ev.data)
				vdev->rx_csum = 1;
			else
				vdev->rx_csum = 0;
			for (i = 0; i < vdev->no_of_vpath; i++) {
				if (vdev->vpaths[i].is_configured)
					vdev->vpaths[i].ring.rx_csum =
						 vdev->rx_csum;
			}
			break;
		}
	case ETHTOOL_SSG:
		{
			struct ethtool_value ev;

			if (copy_from_user(&ev, data, sizeof(ev)))
				return -EFAULT;

			if (ev.data)
				dev->features |= NETIF_F_SG;
			else
				dev->features &= ~NETIF_F_SG;
			break;
		}
#ifdef NETIF_F_TSO
	case ETHTOOL_STSO:
		{
			struct ethtool_value ev;

			if (copy_from_user(&ev, data, sizeof(ev)))
				return -EFAULT;

			if (ev.data)
				dev->features |= NETIF_F_TSO;
			else
				dev->features &= ~NETIF_F_TSO;
			break;
		}
#endif
	case ETHTOOL_GEEPROM:
		{
			break;
		}
	case ETHTOOL_GSTRINGS:
		{
			struct ethtool_gstrings gstrings = { ETHTOOL_GSTRINGS };
			char *strings = NULL;
			int ret = 0, mem_sz = 0;

			if (copy_from_user
			    (&gstrings, data, sizeof(gstrings)))
				return -EFAULT;

			switch (gstrings.string_set) {
			case ETH_SS_TEST:
#ifdef ETHTOOL_GSTATS
			case ETH_SS_STATS:
				vxge_ethtool_get_strings(dev,
					gstrings.string_set, data);
				break;
#endif

			default:
				return -EOPNOTSUPP;
			}

			if (copy_to_user
			    (data, &gstrings, sizeof(gstrings)))
				ret = -EFAULT;
			if (!ret) {
				data +=
				    offsetof(struct ethtool_gstrings,
					     data);
				if (copy_to_user(data, strings, mem_sz))
					ret = -EFAULT;
			}
			kfree(strings);
			if (ret)
				return ret;
			break;
		}
#ifdef VXGE_SELF_TEST
		case ETHTOOL_TEST:
		{
			struct {
				struct ethtool_test ethtest;
				uint64_t data[VXGE_TEST_LEN];
			} test = { {ETHTOOL_TEST} };

			if (copy_from_user(&test.ethtest, data, sizeof(test.ethtest)))
				return -EFAULT;

			vxge_ethtool_test(dev, &test.ethtest, test.data);
			if (copy_to_user(data, &test, sizeof(test)))
				return -EFAULT;

			break;
		}
#endif
#ifdef ETHTOOL_GSTATS
	case ETHTOOL_GSTATS:
		{
			struct ethtool_stats stats;
			int ret;
			u64 *stat_mem;

			if (copy_from_user(&stats, data, sizeof(stats)))
				return -EFAULT;
			stats.n_stats = STAT_LEN;
			stat_mem =
			    kmalloc(stats.n_stats * sizeof(u64), GFP_USER);
			if (!stat_mem)
				return -ENOMEM;

			vxge_get_ethtool_stats(dev, &stats, stat_mem);
			ret = 0;
			if (copy_to_user(data, &stats, sizeof(stats)))
				ret = -EFAULT;
			data += sizeof(stats);
			if (copy_to_user(data, stat_mem,
					 stats.n_stats * sizeof(u64)))
				ret = -EFAULT;
			kfree(stat_mem);
			return ret;
		}
#endif
	default:
		return -EOPNOTSUPP;
	}

	return 0;
}
#else /* SET_ETHTOOL_OPS */

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24))
#ifdef VXGE_SELF_TEST
static int vxge_ethtool_self_test_count(struct net_device *dev)
{
	return VXGE_TEST_LEN;
}
#endif
#endif

static int vxge_ethtool_get_regs_len(struct net_device *dev)
{
	struct vxgedev *vdev = (struct vxgedev *)netdev_priv(dev);
	int size = 0x0, vpath_max;

	/* for privilaged function include mrpcim and common registers also */
	if (__vxge_hw_device_is_privilaged(vdev->devh->host_type,
				vdev->devh->func_id) == VXGE_HW_OK) {
		size = sizeof(struct vxge_hw_mrpcim_reg) + VXGE_MSIX_TABLE_SIZE;
		vpath_max = VXGE_LEN_64_K / sizeof(struct vxge_hw_vpath_reg);
	}
	else
		vpath_max = VXGE_LEN_120_K / sizeof(struct vxge_hw_vpath_reg);

	if (vdev->no_of_vpath < vpath_max)
		vpath_max = vdev->no_of_vpath;

	size += ((sizeof(struct vxge_hw_vpath_reg) * vpath_max) +
		sizeof(struct vxge_hw_common_reg));

	return size;
}

/**
 * vxge_ethtool_gregs - dumps the entire space of Titan into the buffer.
 * @dev: device pointer.
 * @regs: pointer to the structure with parameters given by ethtool for
 * dumping the registers.
 * @space: The input argumnet into which all the registers are dumped.
 *
 * Dumps the vpath register space of Titan NIC into the user given
 * buffer area.
 */
static void vxge_ethtool_gregs(struct net_device *dev,
			struct ethtool_regs *regs, void *space)
{
	int index, offset, vpath_max = 0;
	enum vxge_hw_status status;
	u64 reg, addr, table;
	u64 *reg_space = (u64 *) space;
	struct vxgedev *vdev = (struct vxgedev *)netdev_priv(dev);
	struct __vxge_hw_device  *hldev = (struct __vxge_hw_device *)
					pci_get_drvdata(vdev->pdev);

	regs->len = 0;
	/* maximum len supported by ethtool is 128K. mrpcim registers need 64K.
	 * Calculate number of vpaths for which we can dump registers */

	status = __vxge_hw_device_is_privilaged(vdev->devh->host_type,
				vdev->devh->func_id);
	if (status == VXGE_HW_OK) {
		regs->len = sizeof(struct vxge_hw_mrpcim_reg) +
				VXGE_MSIX_TABLE_SIZE;
		vpath_max = VXGE_LEN_64_K / sizeof(struct vxge_hw_vpath_reg);
	}
	else
		vpath_max = VXGE_LEN_120_K / sizeof(struct vxge_hw_vpath_reg);

	if (vdev->no_of_vpath < vpath_max)
		vpath_max = vdev->no_of_vpath;
	regs->len += ((sizeof(struct vxge_hw_vpath_reg) * vpath_max) +
			sizeof(struct vxge_hw_common_reg));

	regs->version = vdev->pdev->subsystem_device;

	if (status  == VXGE_HW_OK) {
		/* Dump msix table,  start offset : 0x0 */
		for (offset = 0; offset < VXGE_MAX_REQUESTED_MSIX; offset++) {
			status = vxge_hw_dump_msix_table(hldev,
						offset, &addr, &table);
			if (status != VXGE_HW_OK) {
				vxge_debug_init(VXGE_ERR,
					"%s:%d 0x%x Getting msix table dump Failed",
						__func__, __LINE__, offset);
				return;
			}
			*reg_space++ = addr;
			*reg_space++ = table;
		}

		/* Dump mrpcim registers,  start offset : 0x440 */
		for (offset = 0; offset < sizeof(struct vxge_hw_mrpcim_reg);
				offset += 8) {
			status = vxge_hw_mgmt_reg_read(hldev,
					vxge_hw_mgmt_reg_type_mrpcim,
					0, offset, &reg);
			if (status != VXGE_HW_OK) {
				vxge_debug_init(VXGE_ERR,
					"%s:%d Getting mrpcim reg dump Failed",
						__func__, __LINE__);
				return;
			}
			*reg_space++ = reg;
		}
	}

	/**
	 * Dump common registers 
	 * For privileged function start offset : 0xB0D0
	 * For non-privileged function start offset : 0x0
	*/
	for (offset = 0; offset < sizeof(struct vxge_hw_common_reg);
				offset += 8) {
		status = vxge_hw_mgmt_reg_read(hldev,
				vxge_hw_mgmt_reg_type_common,
				0, offset, &reg);
		if (status != VXGE_HW_OK) {
			vxge_debug_init(VXGE_ERR,
				"%s:%d Getting common reg dump Failed",
				__func__, __LINE__);
			return;
		}
		*reg_space++ = reg;
	}

	/**
	 * Dump vpath registers 
	 * For privileged function start offset : 0xC308
	 * For non-privileged function start offset : 0x1238
	*/
	for (index = 0; index < vpath_max; index++) {
		for (offset = 0; offset < sizeof(struct vxge_hw_vpath_reg);
				offset += 8) {
			status = vxge_hw_mgmt_reg_read(hldev,
					vxge_hw_mgmt_reg_type_vpath,
					vdev->vpaths[index].device_id,
					offset, &reg);
			if (status != VXGE_HW_OK) {
				vxge_debug_init(VXGE_ERR,
					"%s:%d Getting vpath reg dump Failed",
						__func__, __LINE__);
				return;
			}
			*reg_space++ = reg;
		}
	}
}

static u32 vxge_get_rx_csum(struct net_device *dev)
{
	struct vxgedev *vdev = (struct vxgedev *)netdev_priv(dev);

	/* dump the pmd info */
	print_pmd_info(vdev);

	return vdev->rx_csum;
}

static int vxge_set_rx_csum(struct net_device *dev, u32 data)
{
	struct vxgedev *vdev = (struct vxgedev *)netdev_priv(dev);

	if (data)
		vdev->rx_csum = 1;
	else
		vdev->rx_csum = 0;

	return 0;
}

#ifdef NETIF_F_RXHASH
static int vxge_set_flags(struct net_device *dev, u32 data)
{
	struct vxgedev *vdev = (struct vxgedev *)netdev_priv(dev);
	enum vxge_hw_status status;

	if (data & ~ETH_FLAG_RXHASH)
		return -EOPNOTSUPP;

	if (!!(data & ETH_FLAG_RXHASH) == vdev->devh->config.rth_en)
		return 0;

	if (netif_running(dev))
		return -EINVAL;

	if (data & ETH_FLAG_RXHASH) {
		vdev->devh->config.rth_en = VXGE_HW_RTH_ENABLE;
		dev->features |= NETIF_F_RXHASH;
	} else {
		vdev->devh->config.rth_en = VXGE_HW_RTH_DISABLE;
		dev->features &= ~NETIF_F_RXHASH;
	}

	/* Since the rth is intermixed the vpath sorting, do not bother to
	 * modify it with the adapter running.  Only allow for modification
	 * while down and reset the adapter after finished.
	 */
	status = vxge_reset_all_vpaths(vdev);
	if (status != VXGE_HW_OK)
		return -EFAULT;

	return 0;
}
#endif

static struct ethtool_ops vxge_ethtool_ops = {
	.get_settings		= vxge_ethtool_gset,
	.set_settings		= vxge_ethtool_sset,
	.get_drvinfo		= vxge_ethtool_gdrvinfo,
	.get_regs_len		= vxge_ethtool_get_regs_len,
	.get_regs		= vxge_ethtool_gregs,
	.get_link		= ethtool_op_get_link,
	.get_pauseparam		= vxge_ethtool_getpause_data,
	.set_pauseparam		= vxge_ethtool_setpause_data,
	.get_rx_csum		= vxge_get_rx_csum,
	.set_rx_csum		= vxge_set_rx_csum,
	.get_tx_csum		= ethtool_op_get_tx_csum,
#ifdef NETIF_F_RXHASH
	.set_flags		= vxge_set_flags,
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 0)
	.set_tx_csum		= ethtool_op_set_tx_hw_csum,
#endif

	.get_sg			= ethtool_op_get_sg,
	.set_sg			= ethtool_op_set_sg,

#ifdef NETIF_F_TSO
	.get_tso		= ethtool_op_get_tso,
	.set_tso		= vxge_ethtool_op_set_tso,

#endif 
	.get_strings		= vxge_ethtool_get_strings,
	.phys_id		= vxge_ethtool_idnic,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24))
	.get_stats_count	= vxge_ethtool_get_stats_count,
#ifdef VXGE_SELF_TEST
	.self_test_count	= vxge_ethtool_self_test_count,
#endif
#else
	.get_sset_count		= vxge_ethtool_get_sset_count,
#endif
	.get_ethtool_stats	= vxge_get_ethtool_stats,
#ifdef VXGE_SELF_TEST
	.self_test		= vxge_ethtool_test
#endif
};

void initialize_ethtool_ops(struct net_device *ndev)
{
	SET_ETHTOOL_OPS(ndev, &vxge_ethtool_ops);
}

#endif /* SET_ETHTOOL_OPS */
