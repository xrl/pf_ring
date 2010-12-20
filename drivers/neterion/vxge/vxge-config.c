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
 * vxge-config.c: Driver for Neterion Inc's X3100 Series 10GbE PCIe I/O
 *                Virtualized Server Adapter.
 * Copyright(c) 2002-2010 Exar Corp.
 ******************************************************************************/
#include <linux/vmalloc.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/pci.h>
#include <linux/version.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29))
#include <linux/pci_hotplug.h>
#endif
#include <linux/delay.h>

#include "vxge-traffic.h"
#include "vxge-config.h"
#include "vxge-main.h"

int vxge_getbitarray(u64 *set, int number)
{
	set += number / 64;
	return (*set & (0x1ULL << (number % 64))) != 0; /* 0 or 1 */
}

void vxge_setbitarray(u64 *set, int number, int value)
{
	set += number / 64;
	if (value)
		*set |= 0x1ULL << (number % 64); /* set bit */
	else
		*set &= ~(0x1ULL << (number % 64)); /* clear bit */
}

void
vxge_hw_get_msg_data(struct __vxge_hw_virtualpath *vpath,
                                struct vxge_hw_msg_data *msg)
{
	u64 val64;
	struct vxge_hw_vpmgmt_reg __iomem *vpmgmt_reg;
	vpmgmt_reg = vpath->vpmgmt_reg;

	val64 = readq(&vpmgmt_reg->srpcim_to_vpath_wmsg);

	msg->msg_type = VXGE_HW_SRPCIM_TO_VPATH_WMSG_GET_MSG_TYPE(val64);
	msg->msg_dst = VXGE_HW_SRPCIM_TO_VPATH_WMSG_GET_MSG_DST(val64);
	msg->msg_src = VXGE_HW_SRPCIM_TO_VPATH_WMSG_GET_MSG_SRC(val64);
	msg->msg_data = VXGE_HW_SRPCIM_TO_VPATH_WMSG_GET_MSG_DATA(val64);
}

static void
vxge_hw_vpath_set_zero_rx_frm_len(struct __vxge_hw_device *hldev, u32 vp_id)
{
	struct vxge_hw_vpath_reg __iomem *vp_reg;
	struct __vxge_hw_virtualpath *vpath;
	u64 val64;

	vpath = &hldev->virtual_paths[vp_id];
	vp_reg = vpath->vp_reg;

	val64 = readq(&vp_reg->rxmac_vcfg0);
	val64 &= ~VXGE_HW_RXMAC_VCFG0_RTS_MAX_FRM_LEN(0x3fff);
	writeq(val64, &vp_reg->rxmac_vcfg0);
	val64 = readq(&vp_reg->rxmac_vcfg0);

	return;
}

/*
 * vxge_hw_vpath_wait_receive_idle - Wait for Rx to become idle
 *
 * Bug: Receive path stuck during small frames blast test after numerous vpath
 * reset cycle
 *
 * Fix: Driver work-around is to ensure that the vpath queue in the FB (frame
 * buffer) is empty before reset is asserted. In order to do this driver needs
 * to stop RxMAC from sending frames to the queue, e.g., by configuring the
 * max frame length for the vpath to 0 or some small value. Driver then polls
 * WRDMA registers to check that the ring controller for the vpath is not
 * processing frames for a period of time (while having enough RxDs to do so).
 *
 * Poll 2 registers in the WRDMA, namely the FRM_IN_PROGRESS_CNT_VPn register
 * and the PRC_RXD_DOORBELL_VPn register. There is no per-vpath register in
 * the frame buffer that indicates if the vpath queue is empty, so determine
 * the empty state with 2 conditions:
 * 1. There are no frames currently being processed in the WRDMA for
 * the vpath, and
 * 2. The ring controller for the vpath is not being starved of RxDs
 * (otherwise it will not be able to process frames even though the FB vpath
 * queue is not empty).
 *
 * For the second condition, compare the read value of PRC_RXD_DOORBELL_VPn
 * register against the RXD_SPAT value for the vpath.
 * The ring controller will not attempt to fetch RxDs until it has at least
 * RXD_SPAT qwords in the doorbell. A factor of 2 is used just to be safe.
 * Additionally, it is also possible that the ring controller is not
 * processing frames because of arbitration. The chance of this is very small,
 * and we try to reduce it even further by checking that the 2 conditions above
 * hold in 3 successive polls. This bug does not occur when frames from the
 * reset vpath are not selected back-to-back due to arbitration.
 *
 * @hldev: HW device handle.
 * @vp_id: Vpath ID.
 * Returns
 * 	int
 */
int vxge_hw_vpath_wait_receive_idle(struct __vxge_hw_device *hldev, u32 vp_id)
{
	struct vxge_hw_vpath_reg __iomem *vp_reg;
	struct __vxge_hw_virtualpath *vpath;
	u64 val64, rxd_count, rxd_spat;
	int count = 0, total_count = 0;

	vpath = &hldev->virtual_paths[vp_id];
	vp_reg = vpath->vp_reg;

	vxge_hw_vpath_set_zero_rx_frm_len(hldev, vp_id);

	/* Check that the ring controller for this vpath has enough free RxDs
	 * to send frames to the host.  This is done by reading the
	 * PRC_RXD_DOORBELL_VPn register and comparing the read value to the
	 * RXD_SPAT value for the vpath.
	 */
	val64 = readq(&vp_reg->prc_cfg6);
	rxd_spat = VXGE_HW_PRC_CFG6_GET_RXD_SPAT(val64) + 1;
	/* Use a factor of 2 when comparing rxd_count against rxd_spat for some
	 * leg room.
	 */
	rxd_spat *= 2;

	do {
		if (in_interrupt())
			vxge_mdelay(10);
		else
			msleep(10);

		rxd_count = readq(&vp_reg->prc_rxd_doorbell);

		/* Check that the ring controller for this vpath does
		 * not have any frame in its pipeline.
		 */
		val64 = readq(&vp_reg->frm_in_progress_cnt);
		if ((rxd_count <= rxd_spat) || (val64 > 0))
			count = 0;
		else
			count++;
		total_count++;
	} while ((count < VXGE_HW_MIN_SUCCESSIVE_IDLE_COUNT) &&
			(total_count < VXGE_HW_MAX_POLLING_COUNT));

	if (total_count >= VXGE_HW_MAX_POLLING_COUNT)
		printk(KERN_ALERT "%s: Still Receiving traffic. Abort wait\n",
			__func__);

	return total_count;
}

/* vxge_hw_device_wait_receive_idle - This function waits until all frames
 * stored in the frame buffer for each vpath assigned to the given
 * function (hldev) have been sent to the host.
 */
void vxge_hw_device_wait_receive_idle(struct __vxge_hw_device *hldev)
{
	int i, total_count = 0;

	for (i = 0; i < VXGE_HW_MAX_VIRTUAL_PATHS; i++) {
		if (!(hldev->vpaths_deployed & vxge_mBIT(i)))
			continue;

		total_count += vxge_hw_vpath_wait_receive_idle(hldev, i);
		if (total_count >= VXGE_HW_MAX_POLLING_COUNT)
			break;
	}
}

enum vxge_hw_status
vxge_hw_priority_set(struct __vxge_hw_device *hldev, u64 vp_id)
{
	enum vxge_hw_status status = VXGE_HW_OK;
	u32 action = VXGE_HW_BW_CONTROL;
	u64 data0 = 0x0, data1 = 0x0, steer_ctrl = 0x0;
	u32 prio = hldev->config.vp_config[vp_id].vp_prio;
	u32 fw_memo = VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL_FW_MEMO;

	status = __vxge_hw_device_is_privilaged(hldev->host_type,
						hldev->func_id);
	if (status != VXGE_HW_OK)
		return status;

	/*Get the bw and prio settings and then perform a read modify write */
	data0 = 1;
	data0 |= vp_id << 32;

	status = vxge_hw_vpath_fw_api(hldev, 0, action, 0x0,
					fw_memo, &data0, &data1, &steer_ctrl);

	if (status != VXGE_HW_OK)
		return status;

	/* Now set the new priority value for both tx and rx */
	data0 = 0;
	data0 |= vp_id << 32;

	if (prio != VXGE_HW_VPATH_PRIORITY_DEFAULT) {
		data1 &= ~VXGE_HW_RTS_ACCESS_STEER_DATA1_SET_RX_PRIORITY(0x7);
		data1 &= ~VXGE_HW_RTS_ACCESS_STEER_DATA1_SET_TX_PRIORITY(0x7);
		data1 |= VXGE_HW_RTS_ACCESS_STEER_DATA1_SET_RX_PRIORITY(prio);
		data1 |= VXGE_HW_RTS_ACCESS_STEER_DATA1_SET_TX_PRIORITY(prio);

		status = vxge_hw_vpath_fw_api(hldev, 0, action, 0,
					fw_memo, &data0, &data1, &steer_ctrl);
	}

	return status;
}

/*
 * vxge_hw_tx_bw_get - Get the vpath tx bw and priority
 * @hldev: HW device handle.
 * vp_id: vpath id
 * Returns
 *	VXGE_HW_OK on success else
 *	VXGE_HW_FAIL or VXGE_HW_ERR_INVALID_HANDLE
 */
enum vxge_hw_status
vxge_hw_tx_bw_get(struct __vxge_hw_device *hldev, u64 vp_id)
{
	enum vxge_hw_status status = VXGE_HW_OK;
	u32 action = VXGE_HW_BW_CONTROL;
	u64 data0 = 0x0, data1 = 0x0, steer_ctrl = 0x0;
	u64 tx_min_bw = 0, tx_max_bw = 0, tx_pri = 0;
	u32 fw_memo = VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL_FW_MEMO;

	status = __vxge_hw_device_is_privilaged(hldev->host_type,
						hldev->func_id);

	if (status != VXGE_HW_OK)
		return status;

	/* Get the tx bandwidth and tx priority settings */
	data0 = 1;
	data0 |= vp_id << 32;

	status = vxge_hw_vpath_fw_api(hldev, 0, action, 0x0,
				fw_memo, &data0, &data1, &steer_ctrl);

	if (status != VXGE_HW_OK)
		return status;

	tx_pri = VXGE_HW_RTS_ACCESS_STEER_DATA1_GET_TX_PRIORITY(data1);
	tx_min_bw = VXGE_HW_RTS_ACCESS_STEER_DATA1_GET_TX_MIN_BW(data1);
	tx_max_bw = VXGE_HW_RTS_ACCESS_STEER_DATA1_GET_TX_MAX_BW(data1);

	/* Bandwidth setting is stored in increments of (10000 / 256)
	 * approximately 39 Mb/s. So revert it back to get the b/w value
	 */
	hldev->config.vp_config[vp_id].tx_bw_limit = (tx_max_bw * 10000) / 256;
	hldev->config.vp_config[vp_id].vp_prio = tx_pri;

	return status;

}

/*
 * vxge_hw_tx_bw_set - Set the vpath tx bw and priority
 * @hldev: HW device handle.
 * @data0: Get/Set operation
 * @data1: Bandwidth and priority info
 * Returns
 *	VXGE_HW_OK on success else
 *	VXGE_HW_FAIL or VXGE_HW_ERR_INVALID_HANDLE
 */
enum vxge_hw_status
vxge_hw_tx_bw_set(struct __vxge_hw_device *hldev, u64 vp_id)
{
	enum vxge_hw_status status = VXGE_HW_OK;
	u32 action = VXGE_HW_BW_CONTROL;
	u64 data0 = 0x0, data1 = 0x0, steer_ctrl = 0x0, tx_max_bw = 0;
	u32 bandwidth = hldev->config.vp_config[vp_id].tx_bw_limit;
	u32 fw_memo = VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL_FW_MEMO;

	status = __vxge_hw_device_is_privilaged(hldev->host_type,
			hldev->func_id);

	if (status != VXGE_HW_OK)
		return status;

	/* Get the bandwidth and priority settings and then perform a read
	 * modify write.
	 */
	data0 = 1;
	data0 |= vp_id << 32;

	status = vxge_hw_vpath_fw_api(hldev, 0, action, 0x0,
					fw_memo, &data0, &data1, &steer_ctrl);

	if (status != VXGE_HW_OK)
		return status;

	/* Set */
	data0 = 0;
	data0 |= vp_id << 32;

	if (bandwidth != VXGE_HW_VPATH_TX_BW_LIMIT_DEFAULT) {
		data1 &= ~VXGE_HW_RTS_ACCESS_STEER_DATA1_SET_TX_MAX_BW(0xff);
		tx_max_bw = (bandwidth * 256) / 10000;
		data1 |=
			VXGE_HW_RTS_ACCESS_STEER_DATA1_SET_TX_MAX_BW(tx_max_bw);

		status = vxge_hw_vpath_fw_api(hldev, 0, action, 0,
					fw_memo, &data0, &data1, &steer_ctrl);
	}

	return status;
}

/*
 *
 */
enum vxge_hw_status
vxge_hw_vpath_contrib_l2_pause_enable (struct __vxge_hw_device *hldev,
					u64 vp_id)
{
	u64 val64;
	struct vxge_hw_vpath_reg __iomem *vp_reg;
	enum vxge_hw_status status = VXGE_HW_OK;
	u32 vp_prio = hldev->config.vp_config[vp_id].vp_prio;

	if ((hldev == NULL) || (hldev->magic != VXGE_HW_DEVICE_MAGIC))
		return VXGE_HW_ERR_INVALID_DEVICE;

	vp_reg = (struct vxge_hw_vpath_reg __iomem *)hldev->vpath_reg[vp_id];
	val64 = readq(&vp_reg->rxmac_vcfg1);

	if (vp_prio == VXGE_HW_VPATH_PRIORITY_HIGH &&
		!(val64 & VXGE_HW_RXMAC_VCFG1_CONTRIB_L2_FLOW)) {
		val64 |= VXGE_HW_RXMAC_VCFG1_CONTRIB_L2_FLOW; 
		writeq(val64, &vp_reg->rxmac_vcfg1);
	}

	return status;
}

/*
 * vxge_hw_non_priv_func_rx_bw_get - Get the rx bw and priority of
 * non-privileged fucntions. Supported only for fw >= 1.8.0
 * @hldev: HW device handle.
 * Returns
 *      VXGE_HW_OK on success else
 *      VXGE_HW_FAIL or VXGE_HW_ERR_INVALID_HANDLE
 */
enum vxge_hw_status
vxge_hw_non_priv_func_rx_bw_get(struct __vxge_hw_device *hldev,
				u32 *rx_bw, u32 *rx_prio)
{
	u32 action = VXGE_HW_RTS_ACCESS_FW_MEMO_ACTION_NON_PRIV_BANDWIDTH_CTRL;
	u64 data0 = 0x0, data1 = 0x0, steer_ctrl = 0x0;
	u64 func_id = hldev->func_id;
	enum vxge_hw_status status = VXGE_HW_OK;
	u32 fw_memo = VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL_FW_MEMO;

        /* Get the rx bandwidth and rx priority settings */
	data0 = 3;
	data0 |= func_id << 32;

	status = vxge_hw_vpath_fw_api(hldev, func_id, action, 0x0,
					fw_memo, &data0, &data1, &steer_ctrl);

	if (status != VXGE_HW_OK)
		return status;

	*rx_prio = VXGE_HW_RTS_ACCESS_STEER_DATA1_GET_RX_PRIORITY(data1);
	*rx_bw = (VXGE_HW_RTS_ACCESS_STEER_DATA1_GET_RX_MAX_BW(data1) *
			10000) / 256;

	return status;
}

/*
 * vxge_hw_rx_bw_get - Get the vpath rx bw and priority
 * @hldev: HW device handle.
 * vp_id: vpath id
 * Returns
 *      VXGE_HW_OK on success else
 *      VXGE_HW_FAIL or VXGE_HW_ERR_INVALID_HANDLE
 */
enum vxge_hw_status
vxge_hw_rx_bw_get(struct __vxge_hw_device *hldev, u64 vp_id)
{
	enum vxge_hw_status status = VXGE_HW_OK;
	u32 action = VXGE_HW_BW_CONTROL;
	u64 data0 = 0x0, data1 = 0x0, steer_ctrl = 0x0;
	u64 rx_min_bw = 0, rx_max_bw = 0, rx_pri = 0;
	u32 fw_memo = VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL_FW_MEMO;

	status = __vxge_hw_device_is_privilaged(hldev->host_type,
						hldev->func_id);

	if (status != VXGE_HW_OK)
		return status;

        /* Get the rx bandwidth and rx priority settings */
	data0 = 1;
	data0 |= vp_id << 32;

	status = vxge_hw_vpath_fw_api(hldev, 0, action, 0x0,
					fw_memo, &data0, &data1, &steer_ctrl);

	if (status != VXGE_HW_OK)
		return status;

	rx_pri = VXGE_HW_RTS_ACCESS_STEER_DATA1_GET_RX_PRIORITY(data1);
	rx_min_bw = VXGE_HW_RTS_ACCESS_STEER_DATA1_GET_RX_MIN_BW(data1);
	rx_max_bw = VXGE_HW_RTS_ACCESS_STEER_DATA1_GET_RX_MAX_BW(data1);

	/* Bandwidth setting is stored in increments of (10000 / 256)
	 * approximately 39 Mb/s. So revert it back to get the b/w value
	 */
	hldev->config.vp_config[vp_id].rx_bw_limit = (rx_max_bw * 10000) / 256;
	hldev->config.vp_config[vp_id].vp_prio = rx_pri;

	return status;

}
/*
 * vxge_hw_rx_bw_set - Set the vpath tx/rx bw and priority
 * @hldev: HW device handle.
 * @data0: Get/Set operation
 * @data1: Bandwidth and priority info
 * Returns
 *	VXGE_HW_OK on success else
 *	VXGE_HW_FAIL or VXGE_HW_ERR_INVALID_HANDLE
 */
enum vxge_hw_status
vxge_hw_rx_bw_set(struct __vxge_hw_device *hldev, u64 vp_id)
{
	enum vxge_hw_status status = VXGE_HW_OK;
	u32 action = VXGE_HW_BW_CONTROL;
	u64 data0 = 0x0, data1 = 0x0, steer_ctrl = 0x0, rx_max_bw = 0;
	u32 bandwidth = hldev->config.vp_config[vp_id].rx_bw_limit;
	u32 fw_memo = VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL_FW_MEMO;

	status = __vxge_hw_device_is_privilaged(hldev->host_type,
			hldev->func_id);
	if (status != VXGE_HW_OK)
		return status;

	/* Get the bandwidth and priority settings and then perform a read
	 * modify write.
	 */
	data0 = 1;
	data0 |= vp_id << 32;

	status = vxge_hw_vpath_fw_api(hldev, 0, action, 0x0,
					fw_memo, &data0, &data1, &steer_ctrl);

	if (status != VXGE_HW_OK)
		return status;

	/* Set */
	data0 = 0;
	data0 |= vp_id << 32;

	if (bandwidth != VXGE_HW_VPATH_RX_BW_LIMIT_DEFAULT) {
		data1 &= ~VXGE_HW_RTS_ACCESS_STEER_DATA1_SET_RX_MAX_BW(0xff);
		rx_max_bw = (bandwidth * 256) / 10000;
		data1 |=
			VXGE_HW_RTS_ACCESS_STEER_DATA1_SET_RX_MAX_BW(rx_max_bw);
		data1 |= VXGE_HW_RTS_ACCESS_STEER_DATA1_SET_VPATH_OR_FUNC(1);

		status = vxge_hw_vpath_fw_api(hldev, 0, action, 0,
					fw_memo, &data0, &data1, &steer_ctrl);
	}

	return status;
}

/*
 * __vxge_hw_get_vpath_no - Get the VPaths associated with a VF
 * @hldev: Pointer to the dev structure
 * @vfid: Virtual function id to retrieve the vpaths
 * Returns
 * @num_vpn: The number of VPaths associated with this VF
 * @max_vpn: The last vpath associated with this VF
 * @min_vpn: The first vpath associated with this VF
 *
 */
enum vxge_hw_status
__vxge_hw_get_vpath_no(
	struct __vxge_hw_device *hldev,
	u32                     vfid,
	u32			*num_vpn,
	u64			*data1)
{
	u64 data0 = 0x0, steer_ctrl = 0x0;
	u32 vhn = 0;
	enum vxge_hw_status status = VXGE_HW_OK;
	u32 action = VXGE_HW_PRIV_VP_ACTION;
	u32 fw_memo = VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL_FW_MEMO;

	data0 = VXGE_HW_RTS_ACCESS_STEER_CTRL_VFID(vfid) |
		VXGE_HW_RTS_ACCESS_STEER_CTRL_VHN(vhn);

	status = vxge_hw_vpath_fw_api(hldev, 0, action, 0,
				fw_memo, &data0, data1, &steer_ctrl);

	if (status == VXGE_HW_OK)
		*num_vpn = (data0 >> 16) & 0xFF;

	return status;
}

/*
 * __vxge_hw_get_priv_fn - Get the privilege func number
 * @hldev:
 * @vf: The privileged function number
 * @vh: The privileged heirarchy
 *
 * Notes: This is to be invoked by the non privilege drivers
 * to get the privilege function number
 */
enum vxge_hw_status
__vxge_hw_get_priv_fn(
	struct __vxge_hw_device *hldev,
	u32			*priv_vf,
	u32			*priv_vh)
{
	u64 data0 = 0, data1 = 0x0, steer_ctrl = 0;
	enum vxge_hw_status status = VXGE_HW_OK;
	u32 action = VXGE_HW_PRIV_FN_ACTION;
	u32 fw_memo = VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL_FW_MEMO;

	if (hldev == NULL)
		return VXGE_HW_ERR_INVALID_HANDLE;

	status = vxge_hw_vpath_fw_api(hldev, 0, action, 0,
				fw_memo, &data0, &data1, &steer_ctrl);

	if (status == VXGE_HW_OK) {
		*priv_vf = data0 & 0xFF;
		*priv_vh = (data0 >> 8) & 0xFF;
	}
	return status;
}

enum vxge_hw_status
vxge_hw_upgrade_read_version(struct __vxge_hw_device *hldev, u32 *major,
	u32 *minor, u32 *build)
{
	u64 data0 = 0, data1 = 0, steer_ctrl = 0;
	enum vxge_hw_status status = VXGE_HW_OK;

	status = vxge_hw_vpath_fw_api(hldev, 0,
			VXGE_HW_FW_UPGRADE_ACTION,
			VXGE_HW_FW_UPGRADE_OFFSET_READ,
			VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL_FW_MEMO,
			&data0, &data1, &steer_ctrl);
	if (status != VXGE_HW_OK)
		return status;

	*major = VXGE_HW_RTS_ACCESS_STEER_DATA0_GET_FW_VER_MAJOR(data0);
	*minor = VXGE_HW_RTS_ACCESS_STEER_DATA0_GET_FW_VER_MINOR(data0);
	*build = VXGE_HW_RTS_ACCESS_STEER_DATA0_GET_FW_VER_BUILD(data0);

	return status;
}

enum vxge_hw_status
vxge_hw_config_restore_defaults(struct __vxge_hw_device *hldev)
{
	enum vxge_hw_status status = VXGE_HW_OK;
	u64 data0 = 0, data1 = 0, steer_ctrl = 0;
	u32 fw_memo = VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL_FW_MEMO;

	status = vxge_hw_vpath_fw_api(hldev, 0,
			VXGE_HW_FW_API_CONFIG_RESTORE_DEFAULTS, 0,
			fw_memo, &data0, &data1, &steer_ctrl);
	if (status != VXGE_HW_OK)
		printk(KERN_ERR "config_restore defaults failed\n");
	return status;
}

enum vxge_hw_status
vxge_hw_vpath_fw_api(struct __vxge_hw_device *hldev,
		u64 vp_id,
		u32 action,
		u32 offset,
		u32 fw_memo,
		u64 *data0,
		u64 *data1,
		u64 *steer_ctrl)
{
	struct vxge_hw_vpath_reg __iomem *vp_reg;
	struct __vxge_hw_virtualpath *vpath;
	enum vxge_hw_status status;
	u32 retry = 0, max_retry = 100;
	u64 val64;

	vpath = &hldev->virtual_paths[vp_id];
	vp_reg = hldev->vpath_reg[vp_id];

	if (vpath->vp_open) {
		max_retry = 3;
		spin_lock(&hldev->vp_reg_lock[vp_id]);
	}

	writeq(*data0, &vp_reg->rts_access_steer_data0);
	wmb();
	writeq(*data1, &vp_reg->rts_access_steer_data1);
	wmb();

	val64 = VXGE_HW_RTS_ACCESS_STEER_CTRL_ACTION(action) |
		VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL(fw_memo) |
		VXGE_HW_RTS_ACCESS_STEER_CTRL_STROBE |
		VXGE_HW_RTS_ACCESS_STEER_CTRL_OFFSET(offset);

	status = __vxge_hw_pio_mem_write64(val64,
			&vp_reg->rts_access_steer_ctrl,
			VXGE_HW_RTS_ACCESS_STEER_CTRL_STROBE,
			VXGE_HW_DEF_DEVICE_POLL_MILLIS);

	/* The __vxge_hw_device_register_poll can udelay for a significant
	 * amount of time, blocking other proccess from the CPU.  If it delays
	 * for ~5secs, a NMI error can occur.  A way around this is to give up
	 * the processor via msleep, but this is not allowed is under lock.
	 * So, only allow it to sleep for ~4secs if open.  Otherwise, delay for
	 * 1sec and sleep for 10ms until the firmware operation has completed
	 * or timed-out.
	 */
	while ((status != VXGE_HW_OK) && (retry++ < max_retry)) {
		if (!vpath->vp_open)
			msleep(10);
		status = __vxge_hw_device_register_poll(
				&vp_reg->rts_access_steer_ctrl,
				VXGE_HW_RTS_ACCESS_STEER_CTRL_STROBE,
				VXGE_HW_DEF_DEVICE_POLL_MILLIS);
	}

	if (status != VXGE_HW_OK) {
		vxge_debug_tx(VXGE_ERR,"%s:%d __vxge_hw_device_register_poll"
				" failed\n", __func__, __LINE__);
		status = VXGE_HW_FAIL;
		goto exit;
	}

	val64 = readq(&vp_reg->rts_access_steer_ctrl);
	if (val64 & VXGE_HW_RTS_ACCESS_STEER_CTRL_RMACJ_STATUS) {
		*data0 = readq(&vp_reg->rts_access_steer_data0);
		*data1 = readq(&vp_reg->rts_access_steer_data1);
		*steer_ctrl = val64;
		status = VXGE_HW_OK;
	} else
		status = VXGE_HW_FAIL;
exit:
	if (vpath->vp_open)
		spin_unlock(&hldev->vp_reg_lock[vp_id]);
	return status;
}

/* Get function mode */
enum vxge_hw_status
vxge_hw_get_func_mode(struct __vxge_hw_device *hldev, u32 *func_mode)
{
	enum vxge_hw_status status = VXGE_HW_OK;
	u64 data0 = 0, data1 = 0, steer_ctrl = 0;
	int vp_id;
	u32 fw_memo = VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL_FW_MEMO;

	/* get the first vpath number assigned to this function */
	vp_id = hldev->first_vp_id;

	status = vxge_hw_vpath_fw_api(hldev, vp_id,
				VXGE_HW_FW_API_GET_FUNC_MODE, 0,
				fw_memo, &data0, &data1, &steer_ctrl);
	if (status == VXGE_HW_OK) {
		*func_mode = VXGE_HW_GET_FUNC_MODE_VAL(data0);
		hldev->config.function_mode = *func_mode;
	}

	return status;
}

/* change function mode */
enum vxge_hw_status
vxge_hw_change_func_mode(struct __vxge_hw_device *hldev, u32 func_mode)
{
	enum vxge_hw_status status = VXGE_HW_OK;
	u64 data0 = (u64)func_mode, data1 = 0x0, steer_ctrl = 0x0;
	u32 fw_memo = VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL_FW_MEMO;

	if ((func_mode < VXGE_HW_FUNCTION_MODE_MIN) ||
		(func_mode > VXGE_HW_FUNCTION_MODE_MAX)) {
		printk(KERN_ERR "Invalid function mode : %d\n", func_mode);
		return VXGE_HW_ERR_INVALID_FUNC_MODE;
	} else if (func_mode == VXGE_HW_FUNCTION_MODE_MULTI_FUNCTION_17) {
		printk(KERN_ERR "Unsupported function mode : %d\n", func_mode);
		return VXGE_HW_ERR_INVALID_FUNC_MODE;
	}

	status = vxge_hw_vpath_fw_api(hldev, 0, VXGE_HW_FW_API_FUNC_MODE, 0,
				fw_memo, &data0, &data1, &steer_ctrl);
	return status;
}

/* Enable Catch basin mode */
enum vxge_hw_status
vxge_hw_change_catch_basin_mode(struct __vxge_hw_device *hldev, u32 cb_mode)
{
	enum vxge_hw_status status = VXGE_HW_OK;
	u64 vp_id, data0 = 0, data1 = 0, steer_ctrl = 0;
	u32 fw_memo = VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL_FW_MEMO;

	/* Get first vpath of this function */
	vp_id = hldev->first_vp_id;

	data0 = (u64) cb_mode;
	if ((cb_mode < VXGE_HW_CATCH_BASIN_MODE_MIN) ||
		(cb_mode > VXGE_HW_CATCH_BASIN_MODE_MAX)) {
		vxge_debug_tx(VXGE_ERR,"%s:%d Invalid catch basin mode %d\n",
			 __func__, __LINE__, cb_mode);
		return VXGE_HW_ERR_INVALID_CATCH_BASIN_MODE;
	}

	/* Enable/Disable the catch basin mode */
	status = vxge_hw_vpath_fw_api(hldev, vp_id,
				    VXGE_HW_FW_API_CATCH_BASIN_MODE, 0,
				    fw_memo, &data0, &data1, &steer_ctrl);

	if (status == VXGE_HW_OK){
		vxge_debug_tx(VXGE_TRACE,
				"%s:%d vxge_hw_vpath_fw_api succeeded\n",
				__func__, __LINE__);
		vxge_debug_tx(VXGE_TRACE,"%s:%d data0 = 0x%llx\n",
				__func__, __LINE__, data0);
	}else
		vxge_debug_tx(VXGE_ERR,"%s:%d vxge_hw_vpath_fw_api failed\n",
				__func__, __LINE__);

	return status;
}

/* change behavior on failure */
enum vxge_hw_status
vxge_hw_set_behavior_on_failure(struct __vxge_hw_device *hldev,
		enum vxge_hw_xmac_nwif_behavior_on_failure behave_on_failure)
{
	enum vxge_hw_status status = VXGE_HW_OK;
	u64 data0 = 0x0, data1 = 0x0, steer_ctrl = 0x0;
	u32 cmd = VXGE_HW_XMAC_NWIF_Cmd_CfgSetBehaviourOnFailure;
	u32 fw_memo = VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL_FW_MEMO;

	if ((behave_on_failure < VXGE_HW_XMAC_NWIF_OnFailure_NoMove) ||
		(behave_on_failure >
			VXGE_HW_XMAC_NWIF_OnFailure_OtherPortBackOnRestore)) {
			printk(KERN_ERR
				"Invalid setting for failure behavior : %d\n",
				behave_on_failure);
			return VXGE_HW_ERR_INVALID_FAILURE_BEHAVIOUR;
	}

	data0 = VXGE_HW_RTS_ACCESS_STEER_DATA0_SET_NWIF_CMD(cmd);
	data1 = behave_on_failure;
	status = vxge_hw_vpath_fw_api(hldev,
				0, VXGE_HW_RTS_ACCESS_FW_MEMO_ACTION_PRIV_NWIF,
				0, fw_memo, &data0, &data1, &steer_ctrl);
	return status;
}

/* override the default dual port mode */
enum vxge_hw_status
vxge_hw_set_port_mode(struct __vxge_hw_device *hldev,
	enum vxge_hw_xmac_nwif_dp_mode port_mode)
{
	enum vxge_hw_status status = VXGE_HW_OK;
	u64 data0 = 0x0, data1 = 0x0, steer_ctrl = 0x0;
	u32 cmd = VXGE_HW_XMAC_NWIF_Cmd_SetMode;
	u32 fw_memo = VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL_FW_MEMO;

	if ((port_mode < VXGE_HW_DP_NP_MODE_DEFAULT) ||
		(port_mode > VXGE_HW_DP_NP_MODE_ACTIVE_ACTIVE)) {
			printk(KERN_ERR "Invalid port mode : %d\n",
				port_mode);
			return VXGE_HW_ERR_INVALID_DP_MODE;
	}

	data0 = VXGE_HW_RTS_ACCESS_STEER_DATA0_SET_NWIF_CMD(cmd);
	data1 = port_mode;
	status = vxge_hw_vpath_fw_api(hldev,
				0, VXGE_HW_RTS_ACCESS_FW_MEMO_ACTION_PRIV_NWIF,
				0, fw_memo, &data0, &data1, &steer_ctrl);
	return status;
}

/* change behavior on failure */
enum vxge_hw_status
vxge_hw_endis_l2_switch(struct __vxge_hw_device *hldev,
	enum vxge_hw_xmac_nwif_l2_switch_status l2_switch)
{
	enum vxge_hw_status status = VXGE_HW_OK;
	u64 data0 = 0x0, data1 = 0x0, steer_ctrl = 0x0;
	u32 cmd = VXGE_HW_XMAC_NWIF_Cmd_CfgDualPort_L2SwitchEnable;
	u32 fw_memo = VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL_FW_MEMO;

	if ((l2_switch < VXGE_HW_XMAC_NWIF_L2_SWITCH_DISABLE) ||
		(l2_switch > VXGE_HW_XMAC_NWIF_L2_SWITCH_ENABLE)) {
			printk(KERN_ERR "Invalid l2 switch state : %d\n",
				l2_switch);
			return VXGE_HW_ERR_INVALID_L2_SWITCH_STATE;
	}

	data0 = VXGE_HW_RTS_ACCESS_STEER_DATA0_SET_NWIF_CMD(cmd);
	data1 = l2_switch;
	status = vxge_hw_vpath_fw_api(hldev,
				0, VXGE_HW_RTS_ACCESS_FW_MEMO_ACTION_PRIV_NWIF,
				0, fw_memo, &data0, &data1, &steer_ctrl);
	return status;
}

/* configure dual port vpath mapping */
enum vxge_hw_status
vxge_hw_config_vpath_map(struct __vxge_hw_device *hldev, u64 port_map)
{
	enum vxge_hw_status status = VXGE_HW_OK;
	u64 data0 = 0x0, data1 = 0x0, steer_ctrl = 0x0;
	u32 cmd = VXGE_HW_XMAC_NWIF_Cmd_CfgDualPort_VPathVector;
	u32 fw_memo = VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL_FW_MEMO;

	data0 = VXGE_HW_RTS_ACCESS_STEER_DATA0_SET_NWIF_CMD(cmd);
	data1 = port_map;
	status = vxge_hw_vpath_fw_api(hldev,
				0, VXGE_HW_RTS_ACCESS_FW_MEMO_ACTION_PRIV_NWIF,
				0, fw_memo, &data0, &data1, &steer_ctrl);
	return status;
}

enum vxge_hw_status
vxge_hw_get_active_config(struct __vxge_hw_device *hldev,
			enum vxge_hw_xmac_nwif_actconfig req_config,
			u64 *cur_config)
{
	enum vxge_hw_status status = VXGE_HW_OK;
	u64 data0 = 0x0, data1 = 0x0, steer_ctrl = 0x0;
	u32 cmd = VXGE_HW_XMAC_NWIF_Cmd_Get_Active_Config;
	u32 fw_memo = VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL_FW_MEMO;

	/* get port mode */
	data0 = VXGE_HW_RTS_ACCESS_STEER_DATA0_SET_NWIF_CMD(cmd) | req_config;
	status = vxge_hw_vpath_fw_api(hldev,
				0, VXGE_HW_RTS_ACCESS_FW_MEMO_ACTION_PRIV_NWIF,
				0, fw_memo, &data0, &data1, &steer_ctrl);
	if (status == VXGE_HW_OK)
		*cur_config = data1;
	return status;
}

/**
 * vxge_hw_vpath_bw_get - Get the bandwidth for a vpath.
 * @hldev: HW device handle.
 * @vp_id: Vpath Id.
 * @tx_bw: Buffer to return Tx Bandwidth
 * @rx_bw: Buffer to return Rx Bandwidth
 *
 * Get the bandwidth for a given vpath
 *
 */
enum vxge_hw_status vxge_hw_vpath_bw_get(
			struct __vxge_hw_device *hldev,
			u32 vp_id,
			u32 *tx_bw, u32 *rx_bw)
{
	enum vxge_hw_status status = VXGE_HW_OK;

	if (vp_id >= VXGE_HW_MAX_VIRTUAL_PATHS) {
		status = VXGE_HW_ERR_VPATH_NOT_AVAILABLE;
		goto exit;
	}
	status = vxge_hw_tx_bw_get(hldev, vp_id);
	if (status == VXGE_HW_OK) {
		status = vxge_hw_rx_bw_get(hldev, vp_id);
		if (status == VXGE_HW_OK) {
			*tx_bw = hldev->config.vp_config[vp_id].tx_bw_limit;
			*rx_bw = hldev->config.vp_config[vp_id].rx_bw_limit;
		}
	}

exit:
	return status;
}

/**
 * vxge_hw_vpath_priority_get - Get the priority for a vpath.
 * @hldev: HW device handle.
 * @vp_id: Vpath Id.
 * @prio: Buffer to return priority
 *
 * Get the priority for a given vpath
 *
 */
enum vxge_hw_status vxge_hw_vpath_priority_get(
			struct __vxge_hw_device *hldev,
			u32 vp_id,
			u32 *vp_prio)
{
	enum vxge_hw_status status = VXGE_HW_OK;

	if (vp_id >= VXGE_HW_MAX_VIRTUAL_PATHS)
		return VXGE_HW_ERR_VPATH_NOT_AVAILABLE;

	status = vxge_hw_rx_bw_get(hldev, vp_id);
	if (status == VXGE_HW_OK)
		*vp_prio = hldev->config.vp_config[vp_id].vp_prio;

	return status;
}

/**
 * vxge_hw_vpath_priority_set - Get the priority for a vpath.
 * @hldev: HW device handle.
 * @vp_id: Vpath Id.
 * @prio: priority of the vpath
 *
 * Set the priority for a given vpath
 *
 */
enum vxge_hw_status vxge_hw_vpath_priority_set(
			struct __vxge_hw_device *hldev,
			u32 vp_id,
			u32 vp_prio)
{
	enum vxge_hw_status status = VXGE_HW_OK;

	if (vp_id >= VXGE_HW_MAX_VIRTUAL_PATHS)
		return VXGE_HW_ERR_VPATH_NOT_AVAILABLE;

	hldev->config.vp_config[vp_id].vp_prio = vp_prio;

	status = vxge_hw_priority_set(hldev, vp_id);

	return status;
}

/**
 * vxge_hw_mrpcim_stats_get - Get the device mrpcim statistics.
 * @hldev: HW Device.
 * @stats: mrpcim stats
 *
 * Returns the device mrpcim stats for the device.
 */
enum vxge_hw_status vxge_hw_mrpcim_stats_get(
			struct __vxge_hw_device *hldev,
			struct vxge_hw_device_stats_mrpcim_info *stats)
{
	enum vxge_hw_status status = VXGE_HW_OK;

	status = __vxge_hw_device_is_privilaged(hldev->host_type,
			hldev->func_id);
	if (status != VXGE_HW_OK)
		goto exit;

	if (hldev->config.stats_read_method == VXGE_HW_STATS_READ_METHOD_DMA) {

		status = __vxge_hw_device_register_poll(
				&hldev->mrpcim_reg->mrpcim_general_cfg2,
				VXGE_HW_MRPCIM_GENERAL_CFG2_MRPCIM_STATS_ENABLE,
				hldev->config.device_poll_millis);
	}

	if (status == VXGE_HW_OK)
		memcpy(stats, hldev->mrpcim_stats,
			sizeof(struct vxge_hw_device_stats_mrpcim_info));

exit:
	return status;
}

/**
 * vxge_hw_device_vpstats_get - Get the Statistics per vpath
 * @hldev: HW device handle.
 * @vpn: Vpath Number
 * @vpath_stats: Buffer to return Statistics on vpaths
 *
 * Get the Statistics of vpath
 *
 */
static enum vxge_hw_status
vxge_hw_device_vpstats_get(struct __vxge_hw_device *hldev,
				u32 vpn,
				struct vxge_hw_vp_xmac_stats *vp_stats)
{
	u64 *val64;
	int i;
	u32 offset = VXGE_VP_STATS_AGGRn_OFFSET;
	enum vxge_hw_status status = VXGE_HW_OK;

	val64 = (u64 *)vp_stats;

	status = __vxge_hw_device_is_privilaged(hldev->host_type,
			hldev->func_id);

	if (status != VXGE_HW_OK)
		goto exit;

	for (i = 0; i < sizeof(struct vxge_hw_vp_xmac_stats) / 8; i++) {
		status = vxge_hw_mrpcim_stats_access(hldev,
					VXGE_HW_STATS_OP_READ,
					vpn,
					(offset  >> 3), val64);
		if (status != VXGE_HW_OK)
			goto exit;

		offset = offset + 8;
		val64++;
	}
exit:
	return status;
}

#ifdef VXGE_SELF_TEST
/*
 * __vxge_hw_start_self_test - Perform a self test on the device
 * @hldev: device handle
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
 *
 */
enum vxge_hw_status
__vxge_hw_start_self_test(
	struct __vxge_hw_device *hldev,
	u64			data0,
	u64			data1)
{
	u32 action = VXGE_HW_PERFORM_SELF_TEST;
	enum vxge_hw_status status = VXGE_HW_OK;
	u64 steer_ctrl;
	u32 fw_memo = VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL_FW_MEMO;

	status = __vxge_hw_device_is_privilaged(hldev->host_type,
			hldev->func_id);
	if (status != VXGE_HW_OK)
		return status;

	status = vxge_hw_vpath_fw_api(hldev, 0, action, 0,
			fw_memo, &data0, &data1, &steer_ctrl);

	return status;
}

/*
 * __vxge_hw_poll_self_test - Check the status of self test
 * @hldev: device handle
 * @data0: Status of the test
 * @data1: Status of the test
 *
 */
enum vxge_hw_status
__vxge_hw_poll_self_test(
	struct __vxge_hw_device *hldev,
	u64			*data0,
	u64			*data1)
{
	struct vxge_hw_vpath_reg __iomem *vp_reg;
	u64 val64 = 0;
	u64 ret1 = 0;
	u64 ret2 = 0;
	u8 code = 0;
	u16 test_status = 0;
	enum vxge_hw_status status = VXGE_HW_OK;

	status = __vxge_hw_device_is_privilaged(hldev->host_type,
			hldev->func_id);
	if (status != VXGE_HW_OK)
		return status;

	vp_reg = (struct vxge_hw_vpath_reg __iomem *) hldev->vpath_reg[0];

	spin_lock(&hldev->vp_reg_lock[0]);
poll:
	status = __vxge_hw_device_register_poll(
			&vp_reg->rts_access_steer_ctrl,
			VXGE_HW_RTS_ACCESS_STEER_CTRL_STROBE,
			WAIT_FACTOR *
			hldev->config.device_poll_millis);

	if (status != VXGE_HW_OK)
		goto exit;

	val64 = readq(&vp_reg->rts_access_steer_ctrl);

	if (val64 & VXGE_HW_RTS_ACCESS_STEER_CTRL_RMACJ_STATUS) {

		ret1 = readq(&vp_reg->rts_access_steer_data0);
		ret2 = readq(&vp_reg->rts_access_steer_data1);
		code = (ret1 >> 56) & 0xFF;
		if (code) {
			/* Test is still in progress */
			status = VXGE_HW_PENDING;
			goto poll;
		} else {
			test_status = (ret1 >> 32) & 0xFF;
			if (!test_status) /* Test passed */
				status = VXGE_HW_OK;
			else if (test_status == 3)
				status = VXGE_HW_FAIL;
			/* Return the details of the test in data0 and data1 */
			*data0 = ret1;
			*data1 = ret2;
		}
	} else
		status = VXGE_HW_FAIL;
exit:
	spin_unlock(&hldev->vp_reg_lock[0]);
	return status;
}
#endif /* VXGE_SELF_TEST */

#define MAX_STAT_STRING_SIZE		50
#define VXGE_HW_AUX_SEPA		' '

#ifdef VXGE_OS_HAS_SNPRINTF
#define __hw_aux_snprintf(retbuf, bufsize, fmt, key, value, retsize) \
	if (bufsize <= 0) return VXGE_HW_ERR_OUT_OF_SPACE; \
	retsize = snprintf(retbuf, bufsize, fmt, key, \
			VXGE_HW_AUX_SEPA, value); \
	if (retsize < 0 || retsize >= bufsize) return VXGE_HW_ERR_OUT_OF_SPACE;
#else
#define __hw_aux_snprintf(retbuf, bufsize, fmt, key, value, retsize) \
	if (bufsize <= 0) return VXGE_HW_ERR_OUT_OF_SPACE; \
	retsize = sprintf(retbuf, fmt, key, VXGE_HW_AUX_SEPA, value); \
	vxge_assert(retsize < bufsize); \
	if (retsize < 0 || retsize >= bufsize) \
		return VXGE_HW_ERR_OUT_OF_SPACE;
#endif

#define __HW_AUX_ENTRY_DECLARE(size, buf) \
	int entrysize = 0, leftsize = size; \
	char *ptr; ptr = buf;

#define __HW_AUX_ENTRY_USE_LOCALS() \
	entrysize = entrysize, leftsize = leftsize;
/* Print only non-zero values */
#define __HW_AUX_ENTRY(key, value, fmt) \
	if (value) {\
		__hw_aux_snprintf(ptr, leftsize, "%s%c"fmt"\n", \
		key, value, entrysize) \
		ptr += entrysize; leftsize -= entrysize;\
	}
/* Macros to print VP stats */
#define __HW_AUX_ENTRY_STATS(key, value, fmt) \
		__hw_aux_snprintf(ptr, leftsize, "%s%c"fmt"\n", \
		key, value, entrysize) \
		ptr += entrysize; leftsize -= entrysize;

#define __HW_AUX_CONFIG_ENTRY(key, value, fmt) do { \
	if (value == VXGE_HW_USE_FLASH_DEFAULT) { \
		__HW_AUX_ENTRY(key, "FLASH DEFAULT", "%s"); \
	} else { \
		__HW_AUX_ENTRY(key, value, fmt); \
	} \
	} while (0);

#define __HW_AUX_ENTRY_END(bufsize, retsize) \
	*retsize = bufsize - leftsize;

/**
 * vxge_hw_aux_device_config_read - Read device configuration.
 * @hldev: HW device handle.
 * @bufsize: Buffer size.
 * @retbuf: Buffer pointer.
 * @retsize: Size of the result. Cannot be greater than @bufsize.
 *
 * Read device configuration,
 *
 * Returns: VXGE_HW_OK - success.
 * VXGE_HW_ERR_INVALID_DEVICE - Device is not valid.
 * VXGE_HW_ERR_VERSION_CONFLICT - Version it not maching.
 *
 * See also: vxge_hw_aux_driver_config_read().
 */
enum vxge_hw_status vxge_hw_aux_device_config_read(struct __vxge_hw_device *hldev,
				int bufsize, char *retbuf, int *retsize)
{
	int i;
	enum vxge_hw_status status;
	struct vxge_hw_device_config *dev_config;
	__HW_AUX_ENTRY_DECLARE(bufsize, retbuf);

	dev_config = (struct vxge_hw_device_config *)
	vmalloc(sizeof(struct vxge_hw_device_config));
	if (dev_config == NULL)
		return VXGE_HW_FAIL;

	status = vxge_hw_mgmt_device_config(hldev, dev_config,
					  sizeof(struct vxge_hw_device_config));
	if (status != VXGE_HW_OK) {
		vfree(dev_config);
		return status;
	}

	__HW_AUX_CONFIG_ENTRY("Latency Timer",
					dev_config->latency_timer, "%u");
	__HW_AUX_CONFIG_ENTRY("Interrupt Mode",
					dev_config->intr_mode, "%u");
	__HW_AUX_CONFIG_ENTRY("Dump on Unknwon Error",
					dev_config->dump_on_unknown, "%u");
	__HW_AUX_CONFIG_ENTRY("Dump on Serious Error",
					dev_config->dump_on_serr, "%u");
	__HW_AUX_CONFIG_ENTRY("Dump on Critical Error",
					dev_config->dump_on_critical, "%u");
	__HW_AUX_CONFIG_ENTRY("Dump on ECC Error",
					dev_config->dump_on_eccerr, "%u");
	__HW_AUX_CONFIG_ENTRY("RTH Enable",
					dev_config->rth_en, "%u");
	__HW_AUX_CONFIG_ENTRY("stats_read_method",
					dev_config->stats_read_method, "%u");
	__HW_AUX_CONFIG_ENTRY("Device Poll Timeout",
					dev_config->device_poll_millis, "%u");
#if !defined(CONFIG_INET_LRO_MODULE) || !defined(VXGE_KERNEL_LRO)
	__HW_AUX_CONFIG_ENTRY("lro_enable",
					dev_config->lro_enable, "%u");
#endif

#ifdef VXGE_TRACE_INTO_CIRCULAR_ARR
	__HW_AUX_CONFIG_ENTRY("Trace buffer size",
					dev_config->tracebuf_size, "%u");
#endif

	for (i = 0; i < VXGE_HW_MAX_VIRTUAL_PATHS; i++) {
		if (!(((struct __vxge_hw_device *)hldev)->vpath_assignments &
			vxge_mBIT(i)))
			continue;

		__HW_AUX_CONFIG_ENTRY("Virtual Path id",
			dev_config->vp_config[i].vp_id, "%u");
		__HW_AUX_CONFIG_ENTRY("mtu",
			dev_config->vp_config[i].mtu, "%u");
		__HW_AUX_CONFIG_ENTRY("RPA Strip VLAN Tag",
			dev_config->vp_config[i].rpa_strip_vlan_tag, "%u");
		__HW_AUX_CONFIG_ENTRY("Buffer Mode",
			dev_config->vp_config[i].ring.buffer_mode, "%u");
		__HW_AUX_CONFIG_ENTRY("Scatter Mode",
			dev_config->vp_config[i].ring.scatter_mode, "%u");

#if defined(VXGE_HW_USE_SW_LRO)

		__HW_AUX_CONFIG_ENTRY("sw_lro_sessions",
			dev_config->vp_config[i].ring.sw_lro_sessions, "%u");
		__HW_AUX_CONFIG_ENTRY("sw_lro_sg_size",
			dev_config->vp_config[i].ring.sw_lro_sg_size, "%u");
		__HW_AUX_CONFIG_ENTRY("sw_lro_frm_len",
			dev_config->vp_config[i].ring.sw_lro_frm_len, "%u");

#endif

		__HW_AUX_CONFIG_ENTRY("Max Frags",
			dev_config->vp_config[i].fifo.max_frags, "%u");
		__HW_AUX_CONFIG_ENTRY("Alignment Size",
			dev_config->vp_config[i].fifo.alignment_size, "%u");
		__HW_AUX_CONFIG_ENTRY("Interrupt Enable",
			dev_config->vp_config[i].fifo.intr, "%u");
		__HW_AUX_CONFIG_ENTRY("No Snoop Bits",
			dev_config->vp_config[i].fifo.no_snoop_bits, "%u");

		__HW_AUX_CONFIG_ENTRY("Interrupt Enable",
			dev_config->vp_config[i].tti.intr_enable, "%u");
		__HW_AUX_CONFIG_ENTRY("BTimer Value",
			dev_config->vp_config[i].tti.btimer_val, "%u");
		__HW_AUX_CONFIG_ENTRY("Timer AC Enable",
			dev_config->vp_config[i].tti.timer_ac_en, "%u");
		__HW_AUX_CONFIG_ENTRY("Timer CI Enable",
			dev_config->vp_config[i].tti.timer_ci_en, "%u");
		__HW_AUX_CONFIG_ENTRY("Timer RI Enable",
			dev_config->vp_config[i].tti.timer_ri_en, "%u");
		__HW_AUX_CONFIG_ENTRY("RTimer Value",
			dev_config->vp_config[i].tti.rtimer_val, "%u");
		__HW_AUX_CONFIG_ENTRY("Util Sel",
			dev_config->vp_config[i].tti.util_sel, "%u");
		__HW_AUX_CONFIG_ENTRY("LTimer Value",
			dev_config->vp_config[i].tti.ltimer_val, "%u");
		__HW_AUX_CONFIG_ENTRY("Util Range A",
			dev_config->vp_config[i].tti.urange_a, "%u");
		__HW_AUX_CONFIG_ENTRY("Util Event Count A",
			dev_config->vp_config[i].tti.uec_a, "%u");
		__HW_AUX_CONFIG_ENTRY("Util Range B",
			dev_config->vp_config[i].tti.urange_b, "%u");
		__HW_AUX_CONFIG_ENTRY("Util Event Count B",
			dev_config->vp_config[i].tti.uec_b, "%u");
		__HW_AUX_CONFIG_ENTRY("Util Range C",
			dev_config->vp_config[i].tti.urange_c, "%u");
		__HW_AUX_CONFIG_ENTRY("Util Event Count C",
			dev_config->vp_config[i].tti.uec_c, "%u");
		__HW_AUX_CONFIG_ENTRY("Util Event Count D",
			dev_config->vp_config[i].tti.uec_d, "%u");

		__HW_AUX_CONFIG_ENTRY("Interrupt Enable",
			dev_config->vp_config[i].rti.intr_enable, "%u");
		__HW_AUX_CONFIG_ENTRY("BTimer Value",
			dev_config->vp_config[i].rti.btimer_val, "%u");
		__HW_AUX_CONFIG_ENTRY("Timer AC Enable",
			dev_config->vp_config[i].rti.timer_ac_en, "%u");
		__HW_AUX_CONFIG_ENTRY("Timer CI Enable",
			dev_config->vp_config[i].rti.timer_ci_en, "%u");
		__HW_AUX_CONFIG_ENTRY("Timer RI Enable",
			dev_config->vp_config[i].rti.timer_ri_en, "%u");
		__HW_AUX_CONFIG_ENTRY("RTimer Value",
			dev_config->vp_config[i].rti.rtimer_val, "%u");
		__HW_AUX_CONFIG_ENTRY("Util Sel",
			dev_config->vp_config[i].rti.util_sel, "%u");
		__HW_AUX_CONFIG_ENTRY("LTimer Value",
			dev_config->vp_config[i].rti.ltimer_val, "%u");
		__HW_AUX_CONFIG_ENTRY("Util Range A",
			dev_config->vp_config[i].rti.urange_a, "%u");
		__HW_AUX_CONFIG_ENTRY("Util Event Count A",
			dev_config->vp_config[i].rti.uec_a, "%u");
		__HW_AUX_CONFIG_ENTRY("Util Range B",
			dev_config->vp_config[i].rti.urange_b, "%u");
		__HW_AUX_CONFIG_ENTRY("Util Event Count B",
			dev_config->vp_config[i].rti.uec_b, "%u");
		__HW_AUX_CONFIG_ENTRY("Util Range C",
			dev_config->vp_config[i].rti.urange_c, "%u");
		__HW_AUX_CONFIG_ENTRY("Util Event Count C",
			dev_config->vp_config[i].rti.uec_c, "%u");
		__HW_AUX_CONFIG_ENTRY("Util Event Count D",
			dev_config->vp_config[i].rti.uec_d, "%u");
	}

	__HW_AUX_ENTRY_END(bufsize, retsize);

	vfree(dev_config);

	return VXGE_HW_OK;
}

/**
 * vxge_hw_aux_stats_vpath_read - Read device vpath statistics.
 * @hldev: HW device handle.
 * @bufsize: Buffer size.
 * @retbuf: Buffer pointer.
 * @retsize: Size of the result. Cannot be greater than @bufsize.
 *
 * Read device vpath statistics for any vpath. This is valid for function 0 device only
 *
 */
enum vxge_hw_status vxge_hw_aux_stats_vpath_read(struct __vxge_hw_device *hldev,
			int bufsize, char *retbuf, int *retsize, u32 vpn)
{
	enum vxge_hw_status status;
	struct vxge_hw_vp_xmac_stats hw_info;

	__HW_AUX_ENTRY_DECLARE(bufsize, retbuf);

	__HW_AUX_ENTRY_USE_LOCALS();

	vxge_assert(hldev);

	status = __vxge_hw_device_is_privilaged(hldev->host_type,
			hldev->func_id);

	if (status != VXGE_HW_OK)
		return status;

	status = vxge_hw_device_vpstats_get(hldev, vpn, &hw_info);

	if (status != VXGE_HW_OK)
		return status;

	__HW_AUX_ENTRY_STATS("tx_ttl_eth_frms          :", (unsigned long long)
			hw_info.tx_stats.tx_ttl_eth_frms, "%llu");
	__HW_AUX_ENTRY_STATS("tx_ttl_eth_octets        :", (unsigned long long)
			hw_info.tx_stats.tx_ttl_eth_octets, "%llu");
	__HW_AUX_ENTRY_STATS("tx_data_octets           :", (unsigned long long)
			hw_info.tx_stats.tx_data_octets, "%llu");
	__HW_AUX_ENTRY_STATS("tx_mcast_frms            :", (unsigned long long)
			hw_info.tx_stats.tx_mcast_frms, "%llu");
	__HW_AUX_ENTRY_STATS("tx_bcast_frms            :", (unsigned long long)
			hw_info.tx_stats.tx_bcast_frms, "%llu");
	__HW_AUX_ENTRY_STATS("tx_ucast_frms            :", (unsigned long long)
			hw_info.tx_stats.tx_ucast_frms, "%llu");
	__HW_AUX_ENTRY_STATS("tx_tagged_frms           :", (unsigned long long)
			hw_info.tx_stats.tx_tagged_frms, "%llu");
	__HW_AUX_ENTRY_STATS("tx_vld_ip                :", (unsigned long long)
			hw_info.tx_stats.tx_vld_ip, "%llu");
	__HW_AUX_ENTRY_STATS("tx_vld_ip_octets         :", (unsigned long long)
			hw_info.tx_stats.tx_vld_ip_octets, "%llu");
	__HW_AUX_ENTRY_STATS("tx_icmp                  :", (unsigned long long)
			hw_info.tx_stats.tx_icmp, "%llu");
	__HW_AUX_ENTRY_STATS("tx_tcp                   :", (unsigned long long)
			hw_info.tx_stats.tx_tcp, "%llu");
	__HW_AUX_ENTRY_STATS("tx_rst_tcp               :", (unsigned long long)
			hw_info.tx_stats.tx_rst_tcp, "%llu");
	__HW_AUX_ENTRY_STATS("tx_udp                   :", (unsigned long long)
			hw_info.tx_stats.tx_udp, "%llu");
	__HW_AUX_ENTRY_STATS("tx_unknown_protocol      :",
			hw_info.tx_stats.tx_unknown_protocol, "%u");
	__HW_AUX_ENTRY_STATS("tx_lost_ip               :",
			hw_info.tx_stats.tx_lost_ip, "%u");
	__HW_AUX_ENTRY_STATS("tx_parse_error           :",
			hw_info.tx_stats.tx_parse_error, "%u");
	__HW_AUX_ENTRY_STATS("tx_tcp_offload           :", (unsigned long long)
			hw_info.tx_stats.tx_tcp_offload, "%llu");
	__HW_AUX_ENTRY_STATS("tx_retx_tcp_offload      :", (unsigned long long)
			hw_info.tx_stats.tx_retx_tcp_offload, "%llu");
	__HW_AUX_ENTRY_STATS("tx_lost_ip_offload       :", (unsigned long long)
			hw_info.tx_stats.tx_lost_ip_offload, "%llu");
	__HW_AUX_ENTRY_STATS("rx_ttl_eth_frms          :", (unsigned long long)
			hw_info.rx_stats.rx_ttl_eth_frms, "%llu");
	__HW_AUX_ENTRY_STATS("rx_vld_frms              :", (unsigned long long)
			hw_info.rx_stats.rx_vld_frms, "%llu");
	__HW_AUX_ENTRY_STATS("rx_offload_frms          :", (unsigned long long)
			hw_info.rx_stats.rx_offload_frms, "%llu");
	__HW_AUX_ENTRY_STATS("rx_ttl_eth_octets        :", (unsigned long long)
			hw_info.rx_stats.rx_ttl_eth_octets, "%llu");
	__HW_AUX_ENTRY_STATS("rx_data_octets           :", (unsigned long long)
			hw_info.rx_stats.rx_data_octets, "%llu");
	__HW_AUX_ENTRY_STATS("rx_offload_octets        :", (unsigned long long)
			hw_info.rx_stats.rx_offload_octets, "%llu");
	__HW_AUX_ENTRY_STATS("rx_vld_mcast_frms        :", (unsigned long long)
			hw_info.rx_stats.rx_vld_mcast_frms, "%llu");
	__HW_AUX_ENTRY_STATS("rx_vld_bcast_frms        :", (unsigned long long)
			hw_info.rx_stats.rx_vld_bcast_frms, "%llu");
	__HW_AUX_ENTRY_STATS("rx_accepted_ucast_frms   :", (unsigned long long)
			hw_info.rx_stats.rx_accepted_ucast_frms, "%llu");
	__HW_AUX_ENTRY_STATS("rx_accepted_nucast_frms  :", (unsigned long long)
			hw_info.rx_stats.rx_accepted_nucast_frms, "%llu");
	__HW_AUX_ENTRY_STATS("rx_tagged_frms           :", (unsigned long long)
			hw_info.rx_stats.rx_tagged_frms, "%llu");
	__HW_AUX_ENTRY_STATS("rx_long_frms             :", (unsigned long long)
			hw_info.rx_stats.rx_long_frms, "%llu");
	__HW_AUX_ENTRY_STATS("rx_usized_frms           :", (unsigned long long)
			hw_info.rx_stats.rx_usized_frms, "%llu");
	__HW_AUX_ENTRY_STATS("rx_osized_frms           :", (unsigned long long)
			hw_info.rx_stats.rx_osized_frms, "%llu");
	__HW_AUX_ENTRY_STATS("rx_frag_frms             :", (unsigned long long)
			hw_info.rx_stats.rx_frag_frms, "%llu");
	__HW_AUX_ENTRY_STATS("rx_jabber_frms           :", (unsigned long long)
			hw_info.rx_stats.rx_jabber_frms, "%llu");
	__HW_AUX_ENTRY_STATS("rx_ttl_64_frms           :", (unsigned long long)
			hw_info.rx_stats.rx_ttl_64_frms, "%llu");
	__HW_AUX_ENTRY_STATS("rx_ttl_65_127_frms       :", (unsigned long long)
			hw_info.rx_stats.rx_ttl_65_127_frms, "%llu");
	__HW_AUX_ENTRY_STATS("rx_ttl_128_255_frms      :", (unsigned long long)
			hw_info.rx_stats.rx_ttl_128_255_frms, "%llu");
	__HW_AUX_ENTRY_STATS("rx_ttl_256_511_frms      :", (unsigned long long)
			hw_info.rx_stats.rx_ttl_256_511_frms, "%llu");
	__HW_AUX_ENTRY_STATS("rx_ttl_512_1023_frms     :", (unsigned long long)
			hw_info.rx_stats.rx_ttl_512_1023_frms, "%llu");
	__HW_AUX_ENTRY_STATS("rx_ttl_1024_1518_frms    :", (unsigned long long)
			hw_info.rx_stats.rx_ttl_1024_1518_frms, "%llu");
	__HW_AUX_ENTRY_STATS("rx_ttl_1519_4095_frms    :", (unsigned long long)
			hw_info.rx_stats.rx_ttl_1519_4095_frms, "%llu");
	__HW_AUX_ENTRY_STATS("rx_ttl_4096_8191_frms    :", (unsigned long long)
			hw_info.rx_stats.rx_ttl_4096_8191_frms, "%llu");
	__HW_AUX_ENTRY_STATS("rx_ttl_8192_max_frms     :", (unsigned long long)
			hw_info.rx_stats.rx_ttl_8192_max_frms, "%llu");
	__HW_AUX_ENTRY_STATS("rx_ttl_gt_max_frms       :", (unsigned long long)
			hw_info.rx_stats.rx_ttl_gt_max_frms, "%llu");
	__HW_AUX_ENTRY_STATS("rx_ip                    :", (unsigned long long)
			hw_info.rx_stats.rx_ip, "%llu");
	__HW_AUX_ENTRY_STATS("rx_accepted_ip           :", (unsigned long long)
			hw_info.rx_stats.rx_accepted_ip, "%llu");
	__HW_AUX_ENTRY_STATS("rx_ip_octets             :", (unsigned long long)
			hw_info.rx_stats.rx_ip_octets, "%llu");
	__HW_AUX_ENTRY_STATS("rx_err_ip                :", (unsigned long long)
			hw_info.rx_stats.rx_err_ip, "%llu");
	__HW_AUX_ENTRY_STATS("rx_icmp                  :", (unsigned long long)
			hw_info.rx_stats.rx_icmp, "%llu");
	__HW_AUX_ENTRY_STATS("rx_tcp                   :", (unsigned long long)
			hw_info.rx_stats.rx_tcp, "%llu");
	__HW_AUX_ENTRY_STATS("rx_udp                   :", (unsigned long long)
			hw_info.rx_stats.rx_udp, "%llu");
	__HW_AUX_ENTRY_STATS("rx_err_tcp               :", (unsigned long long)
			hw_info.rx_stats.rx_err_tcp, "%llu");
	__HW_AUX_ENTRY_STATS("rx_lost_frms             :", (unsigned long long)
			hw_info.rx_stats.rx_lost_frms, "%llu");
	__HW_AUX_ENTRY_STATS("rx_lost_ip               :", (unsigned long long)
			hw_info.rx_stats.rx_lost_ip, "%llu");
	__HW_AUX_ENTRY_STATS("rx_lost_ip_offload       :", (unsigned long long)
			hw_info.rx_stats.rx_lost_ip_offload, "%llu");
	__HW_AUX_ENTRY_STATS("rx_various_discard       :", hw_info.rx_stats.rx_various_discard, "%u");
	__HW_AUX_ENTRY_STATS("rx_sleep_discard         :", hw_info.rx_stats.rx_sleep_discard, "%u");
	__HW_AUX_ENTRY_STATS("rx_red_discard           :", hw_info.rx_stats.rx_red_discard, "%u");
	__HW_AUX_ENTRY_STATS("rx_queue_full_discard    :", hw_info.rx_stats.rx_queue_full_discard, "%u");
	__HW_AUX_ENTRY_STATS("rx_mpa_ok_frms           :", (unsigned long long)
			hw_info.rx_stats.rx_mpa_ok_frms, "%llu");

	__HW_AUX_ENTRY_END(bufsize, retsize);

	return VXGE_HW_OK;

}

/**
 * vxge_hw_aux_stats_mrpcim_read - Read device mrpcim statistics.
 * @hldev: HW device handle.
 * @bufsize: Buffer size.
 * @retbuf: Buffer pointer.
 * @retsize: Size of the result. Cannot be greater than @bufsize.
 *
 * Read device mrpcim statistics. This is valid for function 0 device only
 *
 */
enum vxge_hw_status vxge_hw_aux_stats_mrpcim_read(struct __vxge_hw_device *hldev,
			int bufsize, char *retbuf, int *retsize)
{
	enum vxge_hw_status status;
	struct vxge_hw_device_stats_mrpcim_info *mrpcim_info = NULL;
	char *s = NULL;
	int i;

	__HW_AUX_ENTRY_DECLARE(bufsize, retbuf);

	__HW_AUX_ENTRY_USE_LOCALS();

	vxge_assert(hldev);

	status = __vxge_hw_device_is_privilaged(hldev->host_type,
			hldev->func_id);

	if (status != VXGE_HW_OK)
		return status;

	mrpcim_info = vmalloc(sizeof(struct vxge_hw_device_stats_mrpcim_info));
	if (mrpcim_info == NULL)
		return VXGE_HW_ERR_OUT_OF_MEMORY;

	status = vxge_hw_mrpcim_stats_get(hldev, mrpcim_info);

	if (status != VXGE_HW_OK) {
		vfree (mrpcim_info);
		return status;
	}

	s = vmalloc(sizeof(char) * MAX_STAT_STRING_SIZE);
	if (s == NULL) {
		vfree(mrpcim_info);
		return VXGE_HW_ERR_OUT_OF_MEMORY;
	}

	__HW_AUX_ENTRY_STATS("pic_ini_rd_drop\t\t\t\t:",
		mrpcim_info->pic_ini_rd_drop, "%u");
	__HW_AUX_ENTRY_STATS("pic_ini_wr_drop\t\t\t\t:",
		mrpcim_info->pic_ini_wr_drop, "%u");

	for (i = 0; i < VXGE_HW_TITAN_VPATH_REG_SPACES; i++) {
		snprintf(s, MAX_STAT_STRING_SIZE,
			"pic_wrcrdtarb_ph_crdt_depleted_vplane%d\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->
				     pic_wrcrdtarb_ph_crdt_depleted_vplane[i].
				     pic_wrcrdtarb_ph_crdt_depleted, "%u");
	}

	for (i = 0; i < VXGE_HW_TITAN_VPATH_REG_SPACES; i++) {
		snprintf(s, MAX_STAT_STRING_SIZE,
			"pic_wrcrdtarb_pd_crdt_depleted_vplane%d\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->
				     pic_wrcrdtarb_pd_crdt_depleted_vplane[i].
				     pic_wrcrdtarb_pd_crdt_depleted, "%u");
	}

	for (i = 0; i < VXGE_HW_TITAN_VPATH_REG_SPACES; i++) {
		snprintf(s, MAX_STAT_STRING_SIZE,
			"pic_rdcrdtarb_nph_crdt_depleted_vplane%d\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->
				     pic_rdcrdtarb_nph_crdt_depleted_vplane[i].
				     pic_rdcrdtarb_nph_crdt_depleted, "%u");
	}

	__HW_AUX_ENTRY_STATS("pic_ini_rd_vpin_drop\t\t\t:",
		mrpcim_info->pic_ini_rd_vpin_drop, "%u");
	__HW_AUX_ENTRY_STATS("pic_ini_wr_vpin_drop\t\t\t:",
		mrpcim_info->pic_ini_wr_vpin_drop, "%u");
	__HW_AUX_ENTRY_STATS("pic_genstats_count0\t\t\t:",
		mrpcim_info->pic_genstats_count0, "%u");
	__HW_AUX_ENTRY_STATS("pic_genstats_count1\t\t\t:",
		mrpcim_info->pic_genstats_count1, "%u");
	__HW_AUX_ENTRY_STATS("pic_genstats_count2\t\t\t:",
		mrpcim_info->pic_genstats_count2, "%u");
	__HW_AUX_ENTRY_STATS("pic_genstats_count3\t\t\t:",
		mrpcim_info->pic_genstats_count3, "%u");
	__HW_AUX_ENTRY_STATS("pic_genstats_count4\t\t\t:",
		mrpcim_info->pic_genstats_count4, "%u");
	__HW_AUX_ENTRY_STATS("pic_genstats_count5\t\t\t:",
		mrpcim_info->pic_genstats_count5, "%u");
	__HW_AUX_ENTRY_STATS("pci_rstdrop_cpl\t\t\t\t:",
		mrpcim_info->pci_rstdrop_cpl, "%u");
	__HW_AUX_ENTRY_STATS("pci_rstdrop_msg\t\t\t\t:",
		mrpcim_info->pci_rstdrop_msg, "%u");
	__HW_AUX_ENTRY_STATS("pci_rstdrop_client1\t\t\t:",
		mrpcim_info->pci_rstdrop_client1, "%u");
	__HW_AUX_ENTRY_STATS("pci_rstdrop_client0\t\t\t:",
		mrpcim_info->pci_rstdrop_client0, "%u");
	__HW_AUX_ENTRY_STATS("pci_rstdrop_client2\t\t\t:",
		mrpcim_info->pci_rstdrop_client2, "%u");

	for (i = 0; i < VXGE_HW_TITAN_VPATH_REG_SPACES; i++) {
		snprintf(s, MAX_STAT_STRING_SIZE,
			"pci_depl_cplh_vplane%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->
				     pci_depl_h_vplane[i].pci_depl_cplh, "%u");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"pci_depl_nph_vplane%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->
				     pci_depl_h_vplane[i].pci_depl_nph, "%u");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"pci_depl_ph_vplane%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->
				     pci_depl_h_vplane[i].pci_depl_ph, "%u");
	}

	for (i = 0; i < VXGE_HW_TITAN_VPATH_REG_SPACES; i++) {
		snprintf(s, MAX_STAT_STRING_SIZE,
			"pci_depl_cpld_vplane%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->
				     pci_depl_d_vplane[i].pci_depl_cpld, "%u");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"pci_depl_npd_vplane%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->
				     pci_depl_d_vplane[i].pci_depl_npd, "%u");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"pci_depl_pd_vplane%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->
				     pci_depl_d_vplane[i].pci_depl_pd, "%u");
	}

	for (i = 0; i < VXGE_HW_MAC_MAX_PORTS; i++) {
		snprintf(s, MAX_STAT_STRING_SIZE,
			"tx_ttl_frms_PORT%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].tx_ttl_frms,
				     "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"tx_ttl_octets_PORT%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].tx_ttl_octets,
				     "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"tx_data_octets_PORT%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].tx_data_octets,
				     "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"tx_mcast_frms_PORT%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].tx_mcast_frms,
				     "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"tx_bcast_frms_PORT%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].tx_bcast_frms,
				     "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"tx_ucast_frms_PORT%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].tx_ucast_frms,
				     "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"tx_tagged_frms_PORT%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].tx_tagged_frms,
				     "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"tx_vld_ip_PORT%d\t\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].tx_vld_ip,
				     "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"tx_vld_ip_octets_PORT%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].
				     tx_vld_ip_octets, "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE, "tx_icmp_PORT%d\t\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].tx_icmp,
				     "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE, "tx_tcp_PORT%d\t\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].tx_tcp, "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"tx_rst_tcp_PORT%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].tx_rst_tcp,
				     "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE, "tx_udp_PORT%d\t\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].tx_udp, "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"tx_parse_error_PORT%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].tx_parse_error,
				     "%u");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"tx_unknown_protocol_PORT%d\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->
				     xgmac_port[i].tx_unknown_protocol, "%u");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"tx_pause_ctrl_frms_PORT%d\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].
				     tx_pause_ctrl_frms, "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"tx_marker_pdu_frms_PORT%d\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->
				     xgmac_port[i].tx_marker_pdu_frms, "%u");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"tx_lacpdu_frms_PORT%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].tx_lacpdu_frms,
				     "%u");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"tx_drop_ip_PORT%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s, mrpcim_info->xgmac_port[i].tx_drop_ip,
				     "%u");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"tx_marker_resp_pdu_frms_PORT%d\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->
				     xgmac_port[i].tx_marker_resp_pdu_frms,
				     "%u");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"tx_xgmii_char2_match_PORT%d\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->
				     xgmac_port[i].tx_xgmii_char2_match, "%u");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"tx_xgmii_char1_match_PORT%d\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->
				     xgmac_port[i].tx_xgmii_char1_match, "%u");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"tx_xgmii_column2_match_PORT%d\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->
				     xgmac_port[i].tx_xgmii_column2_match,
				     "%u");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"tx_xgmii_column1_match_PORT%d\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->
				     xgmac_port[i].tx_xgmii_column1_match,
				     "%u");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"tx_any_err_frms_PORT%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].tx_any_err_frms,
				     "%u");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"tx_drop_frms_PORT%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s, mrpcim_info->xgmac_port[i].tx_drop_frms,
				     "%u");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_ttl_frms_PORT%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].rx_ttl_frms,
				     "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_vld_frms_PORT%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].rx_vld_frms,
				     "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_offload_frms_PORT%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].rx_offload_frms,
				     "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_ttl_octets_PORT%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].rx_ttl_octets,
				     "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_data_octets_PORT%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].rx_data_octets,
				     "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_offload_octets_PORT%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].
				     rx_offload_octets, "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_vld_mcast_frms_PORT%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].
				     rx_vld_mcast_frms, "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_vld_bcast_frms_PORT%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].
				     rx_vld_bcast_frms, "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_accepted_ucast_frms_PORT%d\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].
				     rx_accepted_ucast_frms, "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_accepted_nucast_frms_PORT%d\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].
				     rx_accepted_nucast_frms, "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_tagged_frms_PORT%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].rx_tagged_frms,
				     "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_long_frms_PORT%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].rx_long_frms,
				     "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_usized_frms_PORT%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].rx_usized_frms,
				     "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_osized_frms_PORT%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].rx_osized_frms,
				     "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_frag_frms_PORT%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].rx_frag_frms,
				     "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_jabber_frms_PORT%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].rx_jabber_frms,
				     "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_ttl_64_frms_PORT%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].rx_ttl_64_frms,
				     "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_ttl_65_127_frms_PORT%d\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].
				     rx_ttl_65_127_frms, "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_ttl_128_255_frms_PORT%d\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].
				     rx_ttl_128_255_frms, "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_ttl_256_511_frms_PORT%d\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].
				     rx_ttl_256_511_frms, "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_ttl_512_1023_frms_PORT%d\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].
				     rx_ttl_512_1023_frms, "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_ttl_1024_1518_frms_PORT%d\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].
				     rx_ttl_1024_1518_frms, "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_ttl_1519_4095_frms_PORT%d\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].
				     rx_ttl_1519_4095_frms, "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_ttl_4096_8191_frms_PORT%d\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].
				     rx_ttl_4096_8191_frms, "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_ttl_8192_max_frms_PORT%d\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].
				     rx_ttl_8192_max_frms, "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_ttl_gt_max_frms_PORT%d\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].
				     rx_ttl_gt_max_frms, "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE, "rx_ip_PORT%d\t\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].rx_ip, "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_accepted_ip_PORT%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].rx_accepted_ip,
				     "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_ip_octets_PORT%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].rx_ip_octets,
				     "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_err_ip_PORT%d\t\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].rx_err_ip,
				     "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE, "rx_icmp_PORT%d\t\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].rx_icmp,
				     "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE, "rx_tcp_PORT%d\t\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].rx_tcp, "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE, "rx_udp_PORT%d\t\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].rx_udp, "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_err_tcp_PORT%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].rx_err_tcp,
				     "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_pause_cnt_PORT%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].rx_pause_count,
				     "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_pause_ctrl_frms_PORT%d\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].
				     rx_pause_ctrl_frms, "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_unsup_ctrl_frms_PORT%d\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].
				     rx_unsup_ctrl_frms, "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_fcs_err_frms_PORT%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].rx_fcs_err_frms,
				     "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_in_rng_len_err_frms_PORT%d\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].
				     rx_in_rng_len_err_frms, "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_out_rng_len_err_frms_PORT%d\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].
				     rx_out_rng_len_err_frms, "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_drop_frms_PORT%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].rx_drop_frms,
				     "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_discarded_frms_PORT%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].
				     rx_discarded_frms, "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_drop_ip_PORT%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].rx_drop_ip,
				     "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_drp_udp_PORT%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].rx_drop_udp,
				     "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_marker_pdu_frms_PORT%d\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->
				     xgmac_port[i].rx_marker_pdu_frms, "%u");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_lacpdu_frms_PORT%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].rx_lacpdu_frms,
				     "%u");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_unknown_pdu_frms_PORT%d\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->
				     xgmac_port[i].rx_unknown_pdu_frms, "%u");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_marker_resp_pdu_frms_PORT%d\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->
				     xgmac_port[i].rx_marker_resp_pdu_frms,
				     "%u");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_fcs_discard_PORT%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].rx_fcs_discard,
				     "%u");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_illegal_pdu_frms_PORT%d\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->
				     xgmac_port[i].rx_illegal_pdu_frms, "%u");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_switch_discard_PORT%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->
				     xgmac_port[i].rx_switch_discard, "%u");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_len_discard_PORT%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].rx_len_discard,
				     "%u");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_rpa_discard_PORT%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].rx_rpa_discard,
				     "%u");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_l2_mgmt_discard_PORT%d\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->
				     xgmac_port[i].rx_l2_mgmt_discard, "%u");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_rts_discard_PORT%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].rx_rts_discard,
				     "%u");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_trash_discard_PORT%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->
				     xgmac_port[i].rx_trash_discard, "%u");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_buff_full_discard_PORT%d\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->
				     xgmac_port[i].rx_buff_full_discard, "%u");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_red_discard_PORT%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].rx_red_discard,
				     "%u");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_xgmii_ctrl_err_cnt_PORT%d\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->
				     xgmac_port[i].rx_xgmii_ctrl_err_cnt, "%u");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_xgmii_data_err_cnt_PORT%d\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->
				     xgmac_port[i].rx_xgmii_data_err_cnt, "%u");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_xgmii_char1_match_PORT%d\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->
				     xgmac_port[i].rx_xgmii_char1_match, "%u");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_xgmii_err_sym_PORT%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->
				     xgmac_port[i].rx_xgmii_err_sym, "%u");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_xgmii_column1_match_PORT%d\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->
				     xgmac_port[i].rx_xgmii_column1_match,
				     "%u");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_xgmii_char2_match_PORT%d\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->
				     xgmac_port[i].rx_xgmii_char2_match, "%u");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_local_fault_PORT%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].rx_local_fault,
				     "%u");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_xgmii_column2_match_PORT%d\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->
				     xgmac_port[i].rx_xgmii_column2_match,
				     "%u");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_jettison_PORT%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s, mrpcim_info->xgmac_port[i].rx_jettison,
				     "%u");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_remote_fault_PORT%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_port[i].rx_remote_fault,
				     "%u");
	}

	for (i = 0; i < VXGE_HW_MAC_MAX_AGGR_PORTS; i++) {
		snprintf(s, MAX_STAT_STRING_SIZE, "tx_frms_AGGR%d\t\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_aggr[i].tx_frms,
				     "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"tx_data_octets_AGGR%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_aggr[i].tx_data_octets,
				     "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"tx_mcast_frms_AGGR%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_aggr[i].tx_mcast_frms,
				     "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"tx_bcast_frms_AGGR%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_aggr[i].tx_bcast_frms,
				     "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"tx_discarded_frms_AGGR%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_aggr[i].
				     tx_discarded_frms, "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"tx_errored_frms_AGGR%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_aggr[i].tx_errored_frms,
				     "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,"rx_frms_AGGR%d\t\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_aggr[i].rx_frms,
				     "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_data_octets_AGGR%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_aggr[i].rx_data_octets,
				     "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_mcast_frms_AGGR%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_aggr[i].rx_mcast_frms,
				     "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_bcast_frms_AGGR%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_aggr[i].rx_bcast_frms,
				     "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_discarded_frms_AGGR%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_aggr[i].
				     rx_discarded_frms, "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_errored_frms_AGGR%d\t\t\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_aggr[i].rx_errored_frms,
				     "%llu");

		snprintf(s, MAX_STAT_STRING_SIZE,
			"rx_unknown_slow_proto_frms_AGGR%d\t:", i);
		__HW_AUX_ENTRY_STATS(s,
				     mrpcim_info->xgmac_aggr[i].
				     rx_unknown_slow_proto_frms, "%llu");
	}

	__HW_AUX_ENTRY_STATS("xgmac_global_prog_event_gnum0\t\t:",
		(unsigned long long)
		mrpcim_info->xgmac_global_prog_event_gnum0, "%llu");
	__HW_AUX_ENTRY_STATS("xgmac_global_prog_event_gnum1\t\t:",
		(unsigned long long)
		mrpcim_info->xgmac_global_prog_event_gnum1, "%llu");

	__HW_AUX_ENTRY_STATS("xgmac_tx_permitted_frms\t\t\t:",
		mrpcim_info->xgmac_tx_permitted_frms, "%u");

	__HW_AUX_ENTRY_STATS("xgmac_port2_tx_any_frms\t\t\t:",
		mrpcim_info->xgmac_port2_tx_any_frms, "%u");
	__HW_AUX_ENTRY_STATS("xgmac_port1_tx_any_frms\t\t\t:",
		mrpcim_info->xgmac_port1_tx_any_frms, "%u");
	__HW_AUX_ENTRY_STATS("xgmac_port0_tx_any_frms\t\t\t:",
		mrpcim_info->xgmac_port0_tx_any_frms, "%u");

	__HW_AUX_ENTRY_STATS("xgmac_port2_rx_any_frms\t\t\t:",
		mrpcim_info->xgmac_port2_rx_any_frms, "%u");
	__HW_AUX_ENTRY_STATS("xgmac_port1_rx_any_frms\t\t\t:",
		mrpcim_info->xgmac_port1_rx_any_frms, "%u");
	__HW_AUX_ENTRY_STATS("xgmac_port0_rx_any_frms\t\t\t:",
		mrpcim_info->xgmac_port0_rx_any_frms, "%u");

	__HW_AUX_ENTRY_END(bufsize, retsize);

	vfree (s);
	vfree(mrpcim_info);
	return VXGE_HW_OK;
}

/**
 * vxge_hw_aux_reg_dump - Dump regs
 * @devh: HW device handle.
 * @buf: Buffer where the data is returned
 * @reg_type: Type of reg to dump
 * @reg_size: Size of the register set
 *            This is typically the size of the xxx_reg_t struct
 *
 * Dump regs based on reg_type
 */
enum vxge_hw_status
vxge_hw_aux_reg_dump(struct __vxge_hw_device *devh, char *buf,
			enum vxge_hw_mgmt_reg_type reg_type,
			u32 reg_size)
{
	enum vxge_hw_status status = VXGE_HW_OK;
	u32 offset;
	u64 retval;
	int ret = 0;

	for (offset = 0; offset < reg_size; offset += 8) {
		status = vxge_hw_mgmt_reg_read(devh,
					reg_type, 0,
					offset, &retval);
		if (status != VXGE_HW_OK)
			return status;

		if (!retval)
			continue;

		ret += sprintf(buf+ret, "0x%04x:0x%08x%08x|", offset,
			(u32)(retval >> 32), (u32)retval);
	}
	return VXGE_HW_OK;

}

/* __vxge_hw_udp_rth_en_dis: enable/disable UDP RTH hashing
 *
 *	en_dis: 0 to disable UDP RTH hashing
 *		1 to enbale UDP RTH hasing
 */
enum vxge_hw_status
__vxge_hw_udp_rth_en_dis(struct __vxge_hw_vpath_handle *vp, u64 en_dis)
{
	struct __vxge_hw_virtualpath *vpath;
	enum vxge_hw_status status = VXGE_HW_OK;
	u32 action = VXGE_HW_EN_DIS_UDP_RTH;
	u64 data1 = 0x0, steer_ctrl = 0x0;
	u32 fw_memo = VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL_FW_MEMO;

	if (vp == NULL)
		return VXGE_HW_ERR_INVALID_HANDLE;

	vpath = vp->vpath;

	/* only Privilaged driver can enable UDP RTH */
	if (en_dis) {
		status = __vxge_hw_device_is_privilaged(vpath->hldev->host_type,
						vpath->hldev->func_id);
		if (status != VXGE_HW_OK)
			return status;
	}

	status = vxge_hw_vpath_fw_api(vpath->hldev, 0, action, 0,
				fw_memo, &en_dis, &data1, &steer_ctrl);

	return status;
}

/*
 * __vxge_hw_channel_allocate - Allocate memory for channel
 * This function allocates required memory for the channel and various arrays
 * in the channel
 */
struct __vxge_hw_channel*
__vxge_hw_channel_allocate(struct __vxge_hw_vpath_handle *vph,
			   enum __vxge_hw_channel_type type,
	u32 length, u32 per_dtr_space, void *userdata)
{
	struct __vxge_hw_channel *channel;
	struct __vxge_hw_device *hldev;
	int size = 0;
	u32 vp_id;

	hldev = vph->vpath->hldev;
	vp_id = vph->vpath->vp_id;

	switch (type) {
	case VXGE_HW_CHANNEL_TYPE_FIFO:
		size = sizeof(struct __vxge_hw_fifo);
		break;
	case VXGE_HW_CHANNEL_TYPE_RING:
		size = sizeof(struct __vxge_hw_ring);
		break;
	default:
		break;
	}

	channel = kzalloc(size, GFP_KERNEL);
	if (channel == NULL)
		goto exit0;
	INIT_LIST_HEAD(&channel->item);

	channel->common_reg = hldev->common_reg;
	channel->first_vp_id = hldev->first_vp_id;
	channel->type = type;
	channel->devh = hldev;
	channel->vph = vph;
	channel->userdata = userdata;
	channel->per_dtr_space = per_dtr_space;
	channel->length = length;
	channel->vp_id = vp_id;

	channel->dtr_arr = kzalloc(sizeof(void *)*length, GFP_KERNEL);
	if (channel->dtr_arr == NULL)
		goto exit1;
	channel->post_count = 0;
	channel->compl_index = channel->length;
	channel->alloc_index = channel->free_count = channel->length;
	return channel;
exit1:
	__vxge_hw_channel_free(channel);

exit0:
	return NULL;
}

/*
 * __vxge_hw_channel_free - Free memory allocated for channel
 * This function deallocates memory from the channel and various arrays
 * in the channel
 */
void __vxge_hw_channel_free(struct __vxge_hw_channel *channel)
{
	kfree(channel->dtr_arr);
	kfree(channel);
}

/*
 * __vxge_hw_channel_initialize - Initialize a channel
 * This function initializes a channel by properly setting the
 * various references
 */
enum vxge_hw_status
__vxge_hw_channel_initialize(struct __vxge_hw_channel *channel)
{
	struct __vxge_hw_virtualpath *vpath;

	vpath = channel->vph->vpath;
	channel->post_count = 0;
	channel->compl_index = channel->length;
	channel->alloc_index = channel->free_count = channel->length;

	switch (channel->type) {
	case VXGE_HW_CHANNEL_TYPE_FIFO:
		vpath->fifoh = (struct __vxge_hw_fifo *)channel;
		channel->stats = &((struct __vxge_hw_fifo *)
				channel)->stats->common_stats;
		break;
	case VXGE_HW_CHANNEL_TYPE_RING:
		vpath->ringh = (struct __vxge_hw_ring *)channel;
		channel->stats = &((struct __vxge_hw_ring *)
				channel)->stats->common_stats;
		break;
	default:
		break;
	}

	return VXGE_HW_OK;
}

/*
 * __vxge_hw_channel_reset - Resets a channel
 * This function resets a channel by properly setting the various references
 */
enum vxge_hw_status
__vxge_hw_channel_reset(struct __vxge_hw_channel *channel)
{
	channel->post_count = 0;
	channel->compl_index = channel->length;
	channel->alloc_index = channel->free_count = channel->length;

	return VXGE_HW_OK;
}

/*
 * __vxge_hw_device_pci_e_init
 * Initialize certain PCI/PCI-X configuration registers
 * with recommended values. Save config space for future hw resets.
 */
void
__vxge_hw_device_pci_e_init(struct __vxge_hw_device *hldev)
{
	u16 cmd = 0;

	/* Set the PErr Repconse bit and SERR in PCI command register. */
	pci_read_config_word(hldev->pdev, PCI_COMMAND, &cmd);
	cmd |= 0x140;
	pci_write_config_word(hldev->pdev, PCI_COMMAND, cmd);

	return;
}

/*
 * __vxge_hw_device_register_poll
 * Will poll certain register for specified amount of time.
 * Will poll until masked bit is not cleared.
 */
enum vxge_hw_status
__vxge_hw_device_register_poll(void __iomem *reg, u64 mask, u32 max_millis)
{
	u64 val64;
	u32 i;

	udelay(10);

	for (i = 0; i <= 9; i++) {
		val64 = readq(reg);
		if (!(val64 & mask))
			return VXGE_HW_OK;
		udelay(100);
	}

	for (i = 0; i <= max_millis; i++) {
		val64 = readq(reg);
		if (!(val64 & mask))
			return VXGE_HW_OK;
		udelay(1000);
	}

	return VXGE_HW_FAIL;
}

 /* __vxge_hw_device_vpath_reset_in_prog_check - Check if vpath reset
 * in progress
 * This routine checks the vpath reset in progress register is turned zero
 */
enum vxge_hw_status
__vxge_hw_device_vpath_reset_in_prog_check(u64 __iomem *vpath_rst_in_prog)
{
	enum vxge_hw_status status;
	status = __vxge_hw_device_register_poll(vpath_rst_in_prog,
			VXGE_HW_VPATH_RST_IN_PROG_VPATH_RST_IN_PROG(0x1ffff),
			VXGE_HW_DEF_DEVICE_POLL_MILLIS);
	return status;
}

/*
 * __vxge_hw_device_get_legacy_reg
 * This routine gets the legacy register section's memory mapped address and sets the
 * swapper.
 */
static struct vxge_hw_legacy_reg __iomem *
__vxge_hw_device_get_legacy_reg(struct pci_dev *pdev, void __iomem *bar0)
{
	enum vxge_hw_status status;

	struct vxge_hw_legacy_reg __iomem *legacy_reg;
	/* 
	 * If the length of Bar0 is 16MB, then assume that we are configured
	 * in MF8P_VP2 mode and then add 8MB to the legacy_reg offsets
	 */ 
	if (pci_resource_len(pdev, 0) == 0x1000000)
		legacy_reg = (struct vxge_hw_legacy_reg __iomem *)
				(bar0 + 0x800000);
	else
		legacy_reg = (struct vxge_hw_legacy_reg __iomem *)bar0;

	status = __vxge_hw_legacy_swapper_set(legacy_reg);
	if (status != VXGE_HW_OK)
		return NULL;

	return legacy_reg;
}

/*
 * __vxge_hw_device_toc_get
 * This routine sets the swapper and reads the toc pointer and returns the
 * memory mapped address of the toc
 */
static struct vxge_hw_toc_reg __iomem *
__vxge_hw_device_toc_get(void __iomem *bar0,
	struct vxge_hw_legacy_reg __iomem *legacy_reg)
{
	u64 val64;
	struct vxge_hw_toc_reg __iomem *toc = NULL;

	val64 =	readq(&legacy_reg->toc_first_pointer);
	toc = (struct vxge_hw_toc_reg __iomem *)(bar0+val64);

	return toc;
}

/*
 * __vxge_hw_device_reg_addr_get
 * This routine sets the swapper and reads the toc pointer and initializes the
 * register location pointers in the device object. It waits until the ric is
 * completed initializing registers.
 */
enum vxge_hw_status
__vxge_hw_device_reg_addr_get(struct __vxge_hw_device *hldev)
{
	u64 val64;
	u32 i;
	enum vxge_hw_status status = VXGE_HW_OK;

	hldev->legacy_reg = __vxge_hw_device_get_legacy_reg(hldev->pdev,
					hldev->bar0);
	if (hldev->legacy_reg  == NULL) {
		status = VXGE_HW_FAIL;
		goto exit;
	}

	hldev->toc_reg = __vxge_hw_device_toc_get(hldev->bar0,
				hldev->legacy_reg);
	if (hldev->toc_reg  == NULL) {
		status = VXGE_HW_FAIL;
		goto exit;
	}

	val64 = readq(&hldev->toc_reg->toc_common_pointer);
	hldev->common_reg =
	(struct vxge_hw_common_reg __iomem *)(hldev->bar0 + val64);

	val64 = readq(&hldev->toc_reg->toc_mrpcim_pointer);
	hldev->mrpcim_reg =
		(struct vxge_hw_mrpcim_reg __iomem *)(hldev->bar0 + val64);

	for (i = 0; i < VXGE_HW_TITAN_SRPCIM_REG_SPACES; i++) {
		val64 = readq(&hldev->toc_reg->toc_srpcim_pointer[i]);
		hldev->srpcim_reg[i] =
			(struct vxge_hw_srpcim_reg __iomem *)
				(hldev->bar0 + val64);
	}

	for (i = 0; i < VXGE_HW_TITAN_VPMGMT_REG_SPACES; i++) {
		val64 = readq(&hldev->toc_reg->toc_vpmgmt_pointer[i]);
		hldev->vpmgmt_reg[i] =
		(struct vxge_hw_vpmgmt_reg __iomem *)(hldev->bar0 + val64);
	}

	for (i = 0; i < VXGE_HW_TITAN_VPATH_REG_SPACES; i++) {
		val64 = readq(&hldev->toc_reg->toc_vpath_pointer[i]);
		hldev->vpath_reg[i] =
			(struct vxge_hw_vpath_reg __iomem *)
				(hldev->bar0 + val64);
	}

	val64 = readq(&hldev->toc_reg->toc_kdfc);

	switch (VXGE_HW_TOC_GET_KDFC_INITIAL_BIR(val64)) {
	case 0:
		hldev->kdfc = (u8 __iomem *)(hldev->bar0 +
			VXGE_HW_TOC_GET_KDFC_INITIAL_OFFSET(val64));
		break;
	default:
		break;
	}

	status = __vxge_hw_device_vpath_reset_in_prog_check(
			(u64 __iomem *)&hldev->common_reg->vpath_rst_in_prog);
exit:
	return status;
}

/*
 * __vxge_hw_device_access_rights_get: Get Access Rights of the driver
 * This routine returns the Access Rights of the driver
 */
static u32
__vxge_hw_device_access_rights_get(u32 host_type, u32 func_id)
{
	u32 access_rights = VXGE_HW_DEVICE_ACCESS_RIGHT_VPATH;

	switch (host_type) {
	case VXGE_HW_NO_MR_NO_SR_NORMAL_FUNCTION:
		if (func_id == 0) {
			access_rights |= VXGE_HW_DEVICE_ACCESS_RIGHT_MRPCIM |
					VXGE_HW_DEVICE_ACCESS_RIGHT_SRPCIM;
		}
		break;
	case VXGE_HW_MR_NO_SR_VH0_BASE_FUNCTION:
		access_rights |= VXGE_HW_DEVICE_ACCESS_RIGHT_MRPCIM |
				VXGE_HW_DEVICE_ACCESS_RIGHT_SRPCIM;
		break;
	case VXGE_HW_NO_MR_SR_VH0_FUNCTION0:
		access_rights |= VXGE_HW_DEVICE_ACCESS_RIGHT_MRPCIM |
				VXGE_HW_DEVICE_ACCESS_RIGHT_SRPCIM;
		break;
	case VXGE_HW_NO_MR_SR_VH0_VIRTUAL_FUNCTION:
	case VXGE_HW_SR_VH_VIRTUAL_FUNCTION:
	case VXGE_HW_MR_SR_VH0_INVALID_CONFIG:
		break;
	case VXGE_HW_SR_VH_FUNCTION0:
	case VXGE_HW_VH_NORMAL_FUNCTION:
		access_rights |= VXGE_HW_DEVICE_ACCESS_RIGHT_SRPCIM;
		break;
	}

	return access_rights;
}

/*
 * __vxge_hw_device_is_privilaged
 * This routine checks if the device function is privileged or not
 */
enum vxge_hw_status
__vxge_hw_device_is_privilaged(u32 host_type, u32 func_id)
{
	if (__vxge_hw_device_access_rights_get(host_type,
		func_id) &
		VXGE_HW_DEVICE_ACCESS_RIGHT_MRPCIM)
		return VXGE_HW_OK;
	else
		return VXGE_HW_ERR_PRIVILAGED_OPEARATION;
}

/*
 * __vxge_hw_device_host_info_get
 * This routine returns the host type assignments
 */
void __vxge_hw_device_host_info_get(struct __vxge_hw_device *hldev)
{
	u64 val64;
	u32 i;

	val64 = readq(&hldev->common_reg->host_type_assignments);

	hldev->host_type =
	   (u32)VXGE_HW_HOST_TYPE_ASSIGNMENTS_GET_HOST_TYPE_ASSIGNMENTS(val64);

	hldev->vpath_assignments = readq(&hldev->common_reg->vpath_assignments);

	for (i = 0; i < VXGE_HW_MAX_VIRTUAL_PATHS; i++) {

		if (!(hldev->vpath_assignments & vxge_mBIT(i)))
			continue;

		hldev->func_id =
			__vxge_hw_vpath_func_id_get(i, hldev->vpmgmt_reg[i]);

		hldev->access_rights = __vxge_hw_device_access_rights_get(
			hldev->host_type, hldev->func_id);

		hldev->first_vp_id = i;
		break;
	}

	return;
}

/*
 * __vxge_hw_device_initialize
 * Initialize Titan-V hardware.
 */
enum vxge_hw_status __vxge_hw_device_initialize(struct __vxge_hw_device *hldev)
{
	enum vxge_hw_status status = VXGE_HW_OK;

	if ((__vxge_hw_device_is_privilaged(hldev->host_type,
			hldev->func_id)) == VXGE_HW_OK) {

		hldev->mrpcim_stats_block =
			__vxge_hw_blockpool_block_allocate(hldev,
			VXGE_HW_BLOCK_SIZE);

		if (hldev->mrpcim_stats_block == NULL) {
			status = VXGE_HW_ERR_OUT_OF_MEMORY;
			return status;
		}

		hldev->mrpcim_stats =
			(struct vxge_hw_device_stats_mrpcim_info *) \
			hldev->mrpcim_stats_block->memblock;

		memset(hldev->mrpcim_stats, 0,
			sizeof(struct vxge_hw_device_stats_mrpcim_info));

		hldev->stats.hw_dev_info_stats.mrpcim_info =
				hldev->mrpcim_stats;

		hldev->mrpcim_stats_sav =
			&hldev->stats.hw_dev_info_stats.mrpcim_info_sav;

		memset(hldev->mrpcim_stats_sav, 0,
			sizeof(struct vxge_hw_device_stats_mrpcim_info));

		writeq(hldev->mrpcim_stats_block->dma_addr,
			&hldev->mrpcim_reg->mrpcim_stats_start_host_addr);
	}

	return status;
}

/**
 * vxge_hw_device_hw_info_get - Get the hw information
 * Returns the vpath mask that has the bits set for each vpath allocated
 * for the driver, FW version information and the first mac addresse for
 * each vpath
 */
enum vxge_hw_status __devinit
vxge_hw_device_hw_info_get(struct pci_dev *pdev, void __iomem *bar0,
			   struct vxge_hw_device_hw_info *hw_info)
{
	u32 i;
	u64 val64, fw_version;
	struct vxge_hw_toc_reg __iomem *toc;
	struct vxge_hw_mrpcim_reg __iomem *mrpcim_reg;
	struct vxge_hw_common_reg __iomem *common_reg;
	struct vxge_hw_vpath_reg __iomem *vpath_reg;
	struct vxge_hw_vpmgmt_reg __iomem *vpmgmt_reg;
	struct vxge_hw_legacy_reg __iomem *legacy_reg;
	enum vxge_hw_status status;

	memset(hw_info, 0, sizeof(struct vxge_hw_device_hw_info));

	legacy_reg = __vxge_hw_device_get_legacy_reg(pdev, bar0);
	if (legacy_reg  == NULL) {
		status = VXGE_HW_ERR_CRITICAL;
		goto exit;
	}

	toc = __vxge_hw_device_toc_get(bar0, legacy_reg);
	if (toc == NULL) {
		status = VXGE_HW_ERR_CRITICAL;
		goto exit;
	}

	val64 = readq(&toc->toc_common_pointer);
	common_reg = (struct vxge_hw_common_reg __iomem *)(bar0 + val64);

	status = __vxge_hw_device_vpath_reset_in_prog_check(
		(u64 __iomem *)&common_reg->vpath_rst_in_prog);
	if (status != VXGE_HW_OK) {
		vxge_debug_init(VXGE_ERR,
		"%s:%d __vxge_hw_device_vpath_reset_in_prog_check Failed",
			__func__, __LINE__);
		goto exit;
	}

	hw_info->vpath_mask = readq(&common_reg->vpath_assignments);

	val64 = readq(&common_reg->host_type_assignments);

	hw_info->host_type =
	   (u32)VXGE_HW_HOST_TYPE_ASSIGNMENTS_GET_HOST_TYPE_ASSIGNMENTS(val64);

	for (i = 0; i < VXGE_HW_MAX_VIRTUAL_PATHS; i++) {

		if (!((hw_info->vpath_mask) & vxge_mBIT(i)))
			continue;

		val64 = readq(&toc->toc_vpmgmt_pointer[i]);

		vpmgmt_reg = (struct vxge_hw_vpmgmt_reg __iomem *)
				(bar0 + val64);

		hw_info->func_id = __vxge_hw_vpath_func_id_get(i, vpmgmt_reg);
		if (__vxge_hw_device_access_rights_get(hw_info->host_type,
			hw_info->func_id) &
			VXGE_HW_DEVICE_ACCESS_RIGHT_MRPCIM) {

			val64 = readq(&toc->toc_mrpcim_pointer);

			mrpcim_reg = (struct vxge_hw_mrpcim_reg __iomem *)
					(bar0 + val64);

			writeq(0, &mrpcim_reg->xgmac_gen_fw_memo_mask);
			wmb();
		}

		val64 = readq(&toc->toc_vpath_pointer[i]);

		vpath_reg = (struct vxge_hw_vpath_reg __iomem *)(bar0 + val64);

		status = __vxge_hw_vpath_fw_ver_get(i, vpath_reg, hw_info);
		if (status != VXGE_HW_OK) {
			vxge_debug_init(VXGE_ERR,
				"%s:%d __vxge_hw_vpath_fw_ver_get Failed",
				__func__, __LINE__);
			goto exit;
		}

		status = __vxge_hw_vpath_card_info_get(i, vpath_reg, hw_info);
		if (status != VXGE_HW_OK) {
			vxge_debug_init(VXGE_ERR,
				"%s:%d __vxge_hw_vpath_card_info_get Failed",
				__func__, __LINE__);
			goto exit;
		}

		/* FW_API_GET_EPROM_REV_API is supported from 1.6.1 onwards */
		fw_version = VXGE_FW_VER(hw_info->fw_version.major,
					hw_info->fw_version.minor,
					hw_info->fw_version.build);

		if (fw_version >= VXGE_FW_VER(1, 6, 1)) {
			/* Ignoring the return status of
			 * vxge_hw_vpath_eprom_img_ver_get as we do not want to
			 * fail the load because of it.
			 */
			vxge_hw_vpath_eprom_img_ver_get(i, vpath_reg, hw_info);
		}

		break;
	}

	for (i = 0; i < VXGE_HW_MAX_VIRTUAL_PATHS; i++) {

		if (!((hw_info->vpath_mask) & vxge_mBIT(i)))
			continue;

		val64 = readq(&toc->toc_vpath_pointer[i]);
		vpath_reg = (struct vxge_hw_vpath_reg __iomem *)(bar0 + val64);

		status =  __vxge_hw_vpath_addr_get(i, vpath_reg,
				hw_info->mac_addrs[i],
				hw_info->mac_addr_masks[i]);
		if (status != VXGE_HW_OK)
			goto exit;
	}
exit:
	return status;
}

/*
 * vxge_hw_device_initialize - Initialize Titan device.
 * Initialize Titan device. Note that all the arguments of this public API
 * are 'IN', including @hldev. Driver cooperates with
 * OS to find new Titan device, locate its PCI and memory spaces.
 *
 * When done, the driver allocates sizeof(struct __vxge_hw_device) bytes for HW
 * to enable the latter to perform Titan hardware initialization.
 */
enum vxge_hw_status __devinit
vxge_hw_device_initialize(
	struct __vxge_hw_device **devh,
	struct vxge_hw_device_attr *attr,
	struct vxge_hw_device_config *device_config,
	u8 titan1)
{
	u32 i;
	u32 nblocks = 0;
	struct __vxge_hw_device *hldev = NULL;
	enum vxge_hw_status status = VXGE_HW_OK;

	status = __vxge_hw_device_config_check(device_config);
	if (status != VXGE_HW_OK)
		goto exit;

	hldev = (struct __vxge_hw_device *)
			vmalloc(sizeof(struct __vxge_hw_device));
	if (hldev == NULL) {
		status = VXGE_HW_ERR_OUT_OF_MEMORY;
		goto exit;
	}

	memset(hldev, 0, sizeof(struct __vxge_hw_device));
	hldev->magic = VXGE_HW_DEVICE_MAGIC;

	vxge_hw_device_debug_set(hldev, VXGE_ERR, VXGE_COMPONENT_ALL);

	/* apply config */
	memcpy(&hldev->config, device_config,
		sizeof(struct vxge_hw_device_config));

	hldev->bar0 = attr->bar0;
	hldev->pdev = attr->pdev;
	hldev->titan1 = titan1;

	hldev->uld_callbacks.link_up = attr->uld_callbacks.link_up;
	hldev->uld_callbacks.link_down = attr->uld_callbacks.link_down;
	hldev->uld_callbacks.crit_err = attr->uld_callbacks.crit_err;

	__vxge_hw_device_pci_e_init(hldev);

	status = __vxge_hw_device_reg_addr_get(hldev);
	if (status != VXGE_HW_OK){
		vfree(hldev);
		goto exit;
	}

	__vxge_hw_device_host_info_get(hldev);

	/* Incrementing for stats blocks */
	nblocks++;

	for (i = 0; i < VXGE_HW_MAX_VIRTUAL_PATHS; i++) {

		if (!(hldev->vpath_assignments & vxge_mBIT(i)))
			continue;

		if (device_config->vp_config[i].ring.enable ==
			VXGE_HW_RING_ENABLE)
			nblocks += device_config->vp_config[i].ring.ring_blocks;

		if (device_config->vp_config[i].fifo.enable ==
			VXGE_HW_FIFO_ENABLE)
			nblocks += device_config->vp_config[i].fifo.fifo_blocks;
		nblocks++;

		/* Initialize the lock to access vp_reg
		 * while invoking FW APIs
		 */
		spin_lock_init(&hldev->vp_reg_lock[i]);
	}

	if (__vxge_hw_blockpool_create(hldev,
		&hldev->block_pool,
		nblocks) != VXGE_HW_OK) {

		vxge_hw_device_terminate(hldev);
		status = VXGE_HW_ERR_OUT_OF_MEMORY;
		goto exit;
	}

	status = __vxge_hw_device_initialize(hldev);

	if (status != VXGE_HW_OK) {
		vxge_hw_device_terminate(hldev);
		goto exit;
	}

	*devh = hldev;
exit:
	return status;
}

/*
 * vxge_hw_device_terminate - Terminate Titan device.
 * Terminate HW device.
 */
void
vxge_hw_device_terminate(struct __vxge_hw_device *hldev)
{
	vxge_assert(hldev->magic == VXGE_HW_DEVICE_MAGIC);

	hldev->magic = VXGE_HW_DEVICE_DEAD;

	if (hldev->mrpcim_stats_block != NULL) {
		__vxge_hw_blockpool_block_free(hldev, hldev->mrpcim_stats_block);
		hldev->mrpcim_stats_block = NULL;
	}

	__vxge_hw_blockpool_destroy(&hldev->block_pool);

	vfree(hldev);
}

enum vxge_hw_status vxge_hw_device_hw_stats_enable(
						struct __vxge_hw_device *hldev)
{
	u32 i;
	u64 val64;
	enum vxge_hw_status status = VXGE_HW_OK;

	val64 = readq(&hldev->common_reg->stats_cfg0);

	for (i = 0; i < VXGE_HW_MAX_VIRTUAL_PATHS; i++) {

		if (!(hldev->vpaths_deployed & vxge_mBIT(i)) ||
			(hldev->virtual_paths[i].vp_open ==
				VXGE_HW_VP_NOT_OPEN))
			continue;

		memcpy(hldev->virtual_paths[i].hw_stats_sav,
				hldev->virtual_paths[i].hw_stats,
				sizeof(struct vxge_hw_vpath_stats_hw_info));

		if (hldev->config.stats_read_method ==
					VXGE_HW_STATS_READ_METHOD_DMA) {
			val64 |= VXGE_HW_STATS_CFG0_STATS_ENABLE(
			(1 << (16 - i)));
		} else {
			status = __vxge_hw_vpath_stats_get(
					&hldev->virtual_paths[i],
					hldev->virtual_paths[i].hw_stats);
		}

	}

	__vxge_hw_pio_mem_write32_upper((u32)vxge_bVALn(val64, 0, 32),
					&hldev->common_reg->stats_cfg0);

	return status;
}

/*
 * vxge_hw_device_stats_get - Get the device hw statistics.
 * Returns the vpath h/w stats for the device.
 */
enum vxge_hw_status
vxge_hw_device_stats_get(struct __vxge_hw_device *hldev,
			struct vxge_hw_device_stats_hw_info *hw_stats)
{
	u32 i;
	u64 val64 = 0;
	enum vxge_hw_status status = VXGE_HW_OK;

	if (hldev->config.stats_read_method == VXGE_HW_STATS_READ_METHOD_DMA) {

		for (i = 0; i < VXGE_HW_MAX_VIRTUAL_PATHS; i++) {

			if (!(hldev->vpaths_deployed & vxge_mBIT(i)))
				continue;

			val64 |= VXGE_HW_STATS_CFG0_STATS_ENABLE(
							(1 << (16 - i)));

		}

		status = __vxge_hw_device_register_poll(
					&hldev->common_reg->stats_cfg0,
					val64,
					hldev->config.device_poll_millis);

	}

	if (status == VXGE_HW_OK)
		memcpy(hw_stats, &hldev->stats.hw_dev_info_stats,
				sizeof(struct vxge_hw_device_stats_hw_info));

	return status;
}

/*
 * vxge_hw_driver_stats_get - Get the device sw statistics.
 * Returns the vpath s/w stats for the device.
 */
enum vxge_hw_status vxge_hw_driver_stats_get(
			struct __vxge_hw_device *hldev,
			struct vxge_hw_device_stats_sw_info *sw_stats)
{
	enum vxge_hw_status status = VXGE_HW_OK;

	memcpy(sw_stats, &hldev->stats.sw_dev_info_stats,
		sizeof(struct vxge_hw_device_stats_sw_info));

	return status;
}

/*
 * vxge_hw_mrpcim_stats_access - Access the statistics from the given location
 *                           and offset and perform an operation
 * Get the statistics from the given location and offset.
 */
enum vxge_hw_status
vxge_hw_mrpcim_stats_access(struct __vxge_hw_device *hldev,
			    u32 operation, u32 location, u32 offset, u64 *stat)
{
	u64 val64;
	enum vxge_hw_status status = VXGE_HW_OK;

	status = __vxge_hw_device_is_privilaged(hldev->host_type,
				hldev->func_id);
	if (status != VXGE_HW_OK)
		goto exit;

	val64 = VXGE_HW_XMAC_STATS_SYS_CMD_OP(operation) |
		VXGE_HW_XMAC_STATS_SYS_CMD_STROBE |
		VXGE_HW_XMAC_STATS_SYS_CMD_LOC_SEL(location) |
		VXGE_HW_XMAC_STATS_SYS_CMD_OFFSET_SEL(offset);

	status = __vxge_hw_pio_mem_write64(val64,
				&hldev->mrpcim_reg->xmac_stats_sys_cmd,
				VXGE_HW_XMAC_STATS_SYS_CMD_STROBE,
				hldev->config.device_poll_millis);

	if ((status == VXGE_HW_OK) && (operation == VXGE_HW_STATS_OP_READ))
		*stat = readq(&hldev->mrpcim_reg->xmac_stats_sys_data);
	else
		*stat = 0;
exit:
	return status;
}

/*
 * vxge_hw_device_xmac_aggr_stats_get - Get the Statistics on aggregate port
 * Get the Statistics on aggregate port
 */
enum vxge_hw_status
vxge_hw_device_xmac_aggr_stats_get(struct __vxge_hw_device *hldev, u32 port,
				   struct vxge_hw_xmac_aggr_stats *aggr_stats)
{
	u64 *val64;
	int i;
	u32 offset = VXGE_HW_STATS_AGGRn_OFFSET;
	enum vxge_hw_status status = VXGE_HW_OK;

	val64 = (u64 *)aggr_stats;

	status = __vxge_hw_device_is_privilaged(hldev->host_type,
				hldev->func_id);
	if (status != VXGE_HW_OK)
		goto exit;

	for (i = 0; i < sizeof(struct vxge_hw_xmac_aggr_stats) / 8; i++) {
		status = vxge_hw_mrpcim_stats_access(hldev,
					VXGE_HW_STATS_OP_READ,
					VXGE_HW_STATS_LOC_AGGR,
					((offset + (104 * port)) >> 3), val64);
		if (status != VXGE_HW_OK)
			goto exit;

		offset += 8;
		val64++;
	}
exit:
	return status;
}

/*
 * vxge_hw_device_xmac_port_stats_get - Get the Statistics on a port
 * Get the Statistics on port
 */
enum vxge_hw_status
vxge_hw_device_xmac_port_stats_get(struct __vxge_hw_device *hldev, u32 port,
				   struct vxge_hw_xmac_port_stats *port_stats)
{
	u64 *val64;
	enum vxge_hw_status status = VXGE_HW_OK;
	int i;
	u32 offset = 0x0;
	val64 = (u64 *) port_stats;

	status = __vxge_hw_device_is_privilaged(hldev->host_type,
				hldev->func_id);
	if (status != VXGE_HW_OK)
		goto exit;

	for (i = 0; i < sizeof(struct vxge_hw_xmac_port_stats) / 8; i++) {
		status = vxge_hw_mrpcim_stats_access(hldev,
					VXGE_HW_STATS_OP_READ,
					VXGE_HW_STATS_LOC_AGGR,
					((offset + (608 * port)) >> 3), val64);
		if (status != VXGE_HW_OK)
			goto exit;

		offset += 8;
		val64++;
	}

exit:
	return status;
}

/*
 * vxge_hw_device_xmac_stats_get - Get the XMAC Statistics
 * Get the XMAC Statistics
 */
enum vxge_hw_status
vxge_hw_device_xmac_stats_get(struct __vxge_hw_device *hldev,
			      struct vxge_hw_xmac_stats *xmac_stats)
{
	enum vxge_hw_status status = VXGE_HW_OK;
	u32 i;

	status = vxge_hw_device_xmac_aggr_stats_get(hldev,
					0, &xmac_stats->aggr_stats[0]);

	if (status != VXGE_HW_OK)
		goto exit;

	status = vxge_hw_device_xmac_aggr_stats_get(hldev,
				1, &xmac_stats->aggr_stats[1]);
	if (status != VXGE_HW_OK)
		goto exit;

	for (i = 0; i < VXGE_HW_MAC_MAX_MAC_PORT_ID; i++) {

		status = vxge_hw_device_xmac_port_stats_get(hldev,
					i, &xmac_stats->port_stats[i]);
		if (status != VXGE_HW_OK)
			goto exit;
	}

	for (i = 0; i < VXGE_HW_MAX_VIRTUAL_PATHS; i++) {

		if (!(hldev->vpaths_deployed & vxge_mBIT(i)))
			continue;

		status = __vxge_hw_vpath_xmac_tx_stats_get(
					&hldev->virtual_paths[i],
					&xmac_stats->vpath_tx_stats[i]);
		if (status != VXGE_HW_OK)
			goto exit;

		status = __vxge_hw_vpath_xmac_rx_stats_get(
					&hldev->virtual_paths[i],
					&xmac_stats->vpath_rx_stats[i]);
		if (status != VXGE_HW_OK)
			goto exit;
	}
exit:
	return status;
}

/*
 * vxge_hw_device_debug_set - Set the debug module, level and timestamp
 * This routine is used to dynamically change the debug output
 */
void vxge_hw_device_debug_set(struct __vxge_hw_device *hldev,
			      enum vxge_debug_level level, u32 mask)
{
	if (hldev == NULL)
		return;

#if defined(VXGE_DEBUG_TRACE_MASK) || \
	defined(VXGE_DEBUG_ERR_MASK)
	hldev->debug_module_mask = mask;
	hldev->debug_level = level;
#endif

#if defined(VXGE_DEBUG_ERR_MASK)
	hldev->level_err = level & VXGE_ERR;
#endif

#if defined(VXGE_DEBUG_TRACE_MASK)
	hldev->level_trace = level & VXGE_TRACE;
#endif
}

/*
 * vxge_hw_device_error_level_get - Get the error level
 * This routine returns the current error level set
 */
u32 vxge_hw_device_error_level_get(struct __vxge_hw_device *hldev)
{
#if defined(VXGE_DEBUG_ERR_MASK)
	if (hldev == NULL)
		return VXGE_ERR;
	else
		return hldev->level_err;
#else
	return 0;
#endif
}

/*
 * vxge_hw_device_trace_level_get - Get the trace level
 * This routine returns the current trace level set
 */
u32 vxge_hw_device_trace_level_get(struct __vxge_hw_device *hldev)
{
#if defined(VXGE_DEBUG_TRACE_MASK)
	if (hldev == NULL)
		return VXGE_TRACE;
	else
		return hldev->level_trace;
#else
	return 0;
#endif
}
/*
 * vxge_hw_device_debug_mask_get - Get the debug mask
 * This routine returns the current debug mask set
 */
u32 vxge_hw_device_debug_mask_get(struct __vxge_hw_device *hldev)
{
#if defined(VXGE_DEBUG_TRACE_MASK) || defined(VXGE_DEBUG_ERR_MASK)
	if (hldev == NULL)
		return 0;
	return hldev->debug_module_mask;
#else
	return 0;
#endif
}

/*
 * vxge_hw_getpause_data -Pause frame frame generation and reception.
 * Returns the Pause frame generation and reception capability of the NIC.
 */
enum vxge_hw_status vxge_hw_device_getpause_data(struct __vxge_hw_device *hldev,
						 u32 port, u32 *tx, u32 *rx)
{
	u64 val64;
	enum vxge_hw_status status = VXGE_HW_OK;

	if ((hldev == NULL) || (hldev->magic != VXGE_HW_DEVICE_MAGIC)) {
		status = VXGE_HW_ERR_INVALID_DEVICE;
		goto exit;
	}

	if (port >= VXGE_HW_MAC_MAX_MAC_PORT_ID) {
		status = VXGE_HW_ERR_INVALID_PORT;
		goto exit;
	}

	status = __vxge_hw_device_is_privilaged(hldev->host_type,
			hldev->func_id);

	if (status != VXGE_HW_OK)
		goto exit;

	val64 = readq(&hldev->mrpcim_reg->rxmac_pause_cfg_port[port]);
	if (val64 & VXGE_HW_RXMAC_PAUSE_CFG_PORT_GEN_EN)
		*tx = 1;
	if (val64 & VXGE_HW_RXMAC_PAUSE_CFG_PORT_RCV_EN)
		*rx = 1;
exit:
	return status;
}

/*
 * vxge_hw_device_setpause_data -  set/reset pause frame generation.
 * It can be used to set or reset Pause frame generation or reception
 * support of the NIC.
 */

enum vxge_hw_status vxge_hw_device_setpause_data(struct __vxge_hw_device *hldev,
						 u32 port, u32 tx, u32 rx)
{
	u64 val64;
	enum vxge_hw_status status = VXGE_HW_OK;

	if ((hldev == NULL) || (hldev->magic != VXGE_HW_DEVICE_MAGIC)) {
		status = VXGE_HW_ERR_INVALID_DEVICE;
		goto exit;
	}

	if (port >= VXGE_HW_MAC_MAX_MAC_PORT_ID) {
		status = VXGE_HW_ERR_INVALID_PORT;
		goto exit;
	}

	status = __vxge_hw_device_is_privilaged(hldev->host_type,
				hldev->func_id);
	if (status != VXGE_HW_OK)
		goto exit;

	val64 = readq(&hldev->mrpcim_reg->rxmac_pause_cfg_port[port]);
	if (tx)
		val64 |= VXGE_HW_RXMAC_PAUSE_CFG_PORT_GEN_EN;
	else
		val64 &= ~VXGE_HW_RXMAC_PAUSE_CFG_PORT_GEN_EN;
	if (rx)
		val64 |= VXGE_HW_RXMAC_PAUSE_CFG_PORT_RCV_EN;
	else
		val64 &= ~VXGE_HW_RXMAC_PAUSE_CFG_PORT_RCV_EN;

	writeq(val64, &hldev->mrpcim_reg->rxmac_pause_cfg_port[port]);
exit:
	return status;
}

u16 vxge_hw_device_link_width_get(struct __vxge_hw_device *hldev)
{
	int link_width, exp_cap;
	u16 lnk;

	exp_cap = pci_find_capability(hldev->pdev, PCI_CAP_ID_EXP);
	pci_read_config_word(hldev->pdev, exp_cap + PCI_EXP_LNKSTA, &lnk);
	link_width = (lnk & VXGE_HW_PCI_EXP_LNKCAP_LNK_WIDTH) >> 4;
	return link_width;
}

/*
 * __vxge_hw_ring_block_memblock_idx - Return the memblock index
 * This function returns the index of memory block
 */
static inline u32
__vxge_hw_ring_block_memblock_idx(u8 *block)
{
	return (u32)*((u64 *)(block + VXGE_HW_RING_MEMBLOCK_IDX_OFFSET));
}

/*
 * __vxge_hw_ring_block_memblock_idx_set - Sets the memblock index
 * This function sets index to a memory block
 */
static inline void
__vxge_hw_ring_block_memblock_idx_set(u8 *block, u32 memblock_idx)
{
	*((u64 *)(block + VXGE_HW_RING_MEMBLOCK_IDX_OFFSET)) = memblock_idx;
}

/*
 * __vxge_hw_ring_block_next_pointer_set - Sets the next block pointer
 * in RxD block
 * Sets the next block pointer in RxD block
 */
static inline void
__vxge_hw_ring_block_next_pointer_set(u8 *block, dma_addr_t dma_next)
{
	*((u64 *)(block + VXGE_HW_RING_NEXT_BLOCK_POINTER_OFFSET)) = dma_next;
}

/*
 * __vxge_hw_ring_first_block_address_get - Returns the dma address of the
 *             first block
 * Returns the dma address of the first RxD block
 */
u64 __vxge_hw_ring_first_block_address_get(struct __vxge_hw_ring *ring)
{
	struct vxge_hw_mempool_dma *dma_object;

	dma_object = ring->mempool->memblocks_dma_arr;
	vxge_assert(dma_object != NULL);

	return dma_object->addr;
}

/*
 * __vxge_hw_ring_item_dma_addr - Return the dma address of an item
 * This function returns the dma address of a given item
 */
static dma_addr_t __vxge_hw_ring_item_dma_addr(struct vxge_hw_mempool *mempoolh,
					       void *item)
{
	u32 memblock_idx;
	void *memblock;
	struct vxge_hw_mempool_dma *memblock_dma_object;
	ptrdiff_t dma_item_offset;

	/* get owner memblock index */
	memblock_idx = __vxge_hw_ring_block_memblock_idx(item);

	/* get owner memblock by memblock index */
	memblock = mempoolh->memblocks_arr[memblock_idx];

	/* get memblock DMA object by memblock index */
	memblock_dma_object = mempoolh->memblocks_dma_arr + memblock_idx;

	/* calculate offset in the memblock of this item */
	dma_item_offset = (u8 *)item - (u8 *)memblock;

	return memblock_dma_object->addr + dma_item_offset;
}

/*
 * __vxge_hw_ring_rxdblock_link - Link the RxD blocks
 * This function returns the dma address of a given item
 */
static void __vxge_hw_ring_rxdblock_link(struct vxge_hw_mempool *mempoolh,
					 struct __vxge_hw_ring *ring, u32 from,
					 u32 to)
{
	u8 *to_item , *from_item;
	dma_addr_t to_dma;

	/* get "from" RxD block */
	from_item = mempoolh->items_arr[from];
	vxge_assert(from_item);

	/* get "to" RxD block */
	to_item = mempoolh->items_arr[to];
	vxge_assert(to_item);

	/* return address of the beginning of previous RxD block */
	to_dma = __vxge_hw_ring_item_dma_addr(mempoolh, to_item);

	/* set next pointer for this RxD block to point on
	 * previous item's DMA start address */
	__vxge_hw_ring_block_next_pointer_set(from_item, to_dma);
}

enum vxge_hw_status
vxge_hw_dump_msix_table(struct __vxge_hw_device *hldev,
			int vector, u64* addr, u64 *table)
{
	enum vxge_hw_status status = VXGE_HW_OK;

	writeq(VXGE_HW_MSIX_CTL_VECTOR_NO(vector),
			&hldev->mrpcim_reg->msix_ctl);
	writeq(VXGE_HW_WRITE_MSIX_ACCESS_TABLE,
		&hldev->mrpcim_reg->msix_access_table);

	status = __vxge_hw_device_register_poll(
			&hldev->mrpcim_reg->msix_access_table,
			VXGE_HW_WRITE_MSIX_ACCESS_TABLE,
			VXGE_HW_DEF_DEVICE_POLL_MILLIS);
	if (status == VXGE_HW_OK) {
		*addr = readq(&hldev->mrpcim_reg->msix_addr);
		*table = readq(&hldev->mrpcim_reg->msix_table);
	}

	return status;
}

/*
 * __vxge_hw_ring_mempool_item_alloc - Allocate List blocks for RxD
 * block callback
 * This function is callback passed to __vxge_hw_mempool_create to create memory
 * pool for RxD block
 */
static void
__vxge_hw_ring_mempool_item_alloc(struct vxge_hw_mempool *mempoolh,
				  u32 memblock_index,
				  struct vxge_hw_mempool_dma *dma_object,
				  u32 index, u32 is_last)
{
	u32 i;
	void *item = mempoolh->items_arr[index];
	struct __vxge_hw_ring *ring =
		(struct __vxge_hw_ring *)mempoolh->userdata;

	/* format rxds array */
	for (i = 0; i < ring->rxds_per_block; i++) {
		void *rxdblock_priv;
		void *uld_priv;
		struct vxge_hw_ring_rxd_1 *rxdp;

		u32 reserve_index = ring->channel.free_count -
				(index * ring->rxds_per_block + i + 1);
		u32 memblock_item_idx;

		ring->channel.dtr_arr[reserve_index] = ((u8 *)item) +
						i * ring->rxd_size;

		/* Note: memblock_item_idx is index of the item within
		 *       the memblock. For instance, in case of three RxD-blocks
		 *       per memblock this value can be 0, 1 or 2. */
		rxdblock_priv = __vxge_hw_mempool_item_priv(mempoolh,
					memblock_index, item,
					&memblock_item_idx);

		rxdp = (struct vxge_hw_ring_rxd_1 *)
				ring->channel.dtr_arr[reserve_index];

		uld_priv = ((u8 *)rxdblock_priv + ring->rxd_priv_size * i);

		/* pre-format Host_Control */
		rxdp->host_control = (u64)(size_t)uld_priv;
	}

	__vxge_hw_ring_block_memblock_idx_set(item, memblock_index);

	if (is_last) {
		/* link last one with first one */
		__vxge_hw_ring_rxdblock_link(mempoolh, ring, index, 0);
	}

	if (index > 0) {
		/* link this RxD block with previous one */
		__vxge_hw_ring_rxdblock_link(mempoolh, ring, index - 1, index);
	}

	return;
}

/*
 *vxge_hw_ring_replenish - Initial replenish of RxDs
 * This function replenishes the RxDs from reserve array to work array
 */
enum vxge_hw_status
vxge_hw_ring_replenish(struct __vxge_hw_ring *ring)
{
	void *rxd;
	struct __vxge_hw_channel *channel;
	enum vxge_hw_status status = VXGE_HW_OK;

	channel = &ring->channel;

	while (vxge_hw_channel_dtr_count(channel) > 0) {

		status = vxge_hw_ring_rxd_reserve(ring, &rxd);

		vxge_assert(status == VXGE_HW_OK);

		if (ring->rxd_init) {
			status = ring->rxd_init(rxd, channel->userdata);
			if (status != VXGE_HW_OK) {
				vxge_hw_ring_rxd_free(ring, rxd);
				goto exit;
			}
		}

		vxge_hw_ring_rxd_post(ring, rxd);
		}
	status = VXGE_HW_OK;
exit:
	return status;
}

/*
 * __vxge_hw_ring_create - Create a Ring
 * This function creates Ring and initializes it.
 *
 */
enum vxge_hw_status
__vxge_hw_ring_create(struct __vxge_hw_vpath_handle *vp,
		      struct vxge_hw_ring_attr *attr)
{
	enum vxge_hw_status status = VXGE_HW_OK;
	struct __vxge_hw_ring *ring;
	u32 ring_length;
	struct vxge_hw_ring_config *config;
	struct __vxge_hw_device *hldev;
	u32 vp_id;
	struct vxge_hw_mempool_cbs ring_mp_callback;

	if ((vp == NULL) || (attr == NULL)) {
		status = VXGE_HW_FAIL;
		goto exit;
	}

	hldev = vp->vpath->hldev;
	vp_id = vp->vpath->vp_id;

	config = &hldev->config.vp_config[vp_id].ring;

	ring_length = config->ring_blocks *
			vxge_hw_ring_rxds_per_block_get(config->buffer_mode);

	ring = (struct __vxge_hw_ring *)__vxge_hw_channel_allocate(vp,
						VXGE_HW_CHANNEL_TYPE_RING,
						ring_length,
						attr->per_rxd_space,
						attr->userdata);

	if (ring == NULL) {
		status = VXGE_HW_ERR_OUT_OF_MEMORY;
		goto exit;
	}

	vp->vpath->ringh = ring;
	ring->rpa_strip_vlan_tag = vp->vpath->vp_config->rpa_strip_vlan_tag;
	ring->lro_enable = hldev->config.lro_enable;
	ring->aggr_ack = vp->vpath->vp_config->aggr_ack;
	ring->vp_id = vp_id;
	ring->vp_reg = vp->vpath->vp_reg;
	ring->common_reg = hldev->common_reg;
	ring->stats = &vp->vpath->sw_stats->ring_stats;
	ring->config = config;
	ring->callback = attr->callback;
	ring->rxd_init = attr->rxd_init;
	ring->rxd_term = attr->rxd_term;
	ring->buffer_mode = config->buffer_mode;
	ring->tim_rti_cfg1_saved = vp->vpath->tim_rti_cfg1_saved;
	ring->tim_rti_cfg3_saved = vp->vpath->tim_rti_cfg3_saved;
	ring->rxd_qword_limit = config->rxd_qword_limit;

	ring->rxd_size = vxge_hw_ring_rxd_size_get(config->buffer_mode);
	ring->rxd_priv_size =
		sizeof(struct __vxge_hw_ring_rxd_priv) + attr->per_rxd_space;
	ring->per_rxd_space = attr->per_rxd_space;

	ring->rxd_priv_size =
		((ring->rxd_priv_size + VXGE_CACHE_LINE_SIZE - 1) /
		VXGE_CACHE_LINE_SIZE) * VXGE_CACHE_LINE_SIZE;

	/* how many RxDs can fit into one block. Depends on configured
	 * buffer_mode. */
	ring->rxds_per_block =
		vxge_hw_ring_rxds_per_block_get(config->buffer_mode);

	/* calculate actual RxD block private size */
	ring->rxdblock_priv_size = ring->rxd_priv_size * ring->rxds_per_block;
	ring_mp_callback.item_func_alloc = __vxge_hw_ring_mempool_item_alloc;
	ring->mempool = __vxge_hw_mempool_create(hldev,
				VXGE_HW_BLOCK_SIZE,
				VXGE_HW_BLOCK_SIZE,
				ring->rxdblock_priv_size,
				ring->config->ring_blocks,
				ring->config->ring_blocks,
				&ring_mp_callback,
				ring);

	if (ring->mempool == NULL) {
		__vxge_hw_ring_delete(vp);
		return VXGE_HW_ERR_OUT_OF_MEMORY;
	}

	status = __vxge_hw_channel_initialize(&ring->channel);
	if (status != VXGE_HW_OK) {
		__vxge_hw_ring_delete(vp);
		goto exit;
	}

	if ((vp->vpath->hldev->config.lro_enable) &&
		(vp->vpath->hldev->config.lro_enable != VXGE_HW_GRO_ENABLE)) {
		status = __vxge_hw_sw_lro_init(ring);
		if (status != VXGE_HW_OK) {
			__vxge_hw_ring_delete(vp);
			goto exit;
		}
	}

	/* Note:
	 * Specifying rxd_init callback means two things:
	 * 1) rxds need to be initialized by driver at channel-open time;
	 * 2) rxds need to be posted at channel-open time
	 *    (that's what the initial_replenish() below does)
	 * Currently we don't have a case when the 1) is done without the 2).
	 */

	if (ring->rxd_init) {
		status = vxge_hw_ring_replenish(ring);
		if (status != VXGE_HW_OK) {
			__vxge_hw_ring_delete(vp);
			goto exit;
		}
	}

	/* initial replenish will increment the counter in its post() routine,
	 * we have to reset it */
	ring->stats->common_stats.usage_cnt = 0;
exit:
	return status;
}

/*
 * __vxge_hw_ring_abort - Returns the RxD
 * This function terminates the RxDs of ring
 */
enum vxge_hw_status __vxge_hw_ring_abort(struct __vxge_hw_ring *ring)
{
	void *rxdh;
	struct __vxge_hw_channel *channel;

	channel = &ring->channel;

	for (;;) {
		vxge_hw_channel_dtr_try_complete(channel, &rxdh);

		if (rxdh == NULL)
			break;

		vxge_hw_channel_dtr_complete(channel);

		if (ring->rxd_term)
			ring->rxd_term(rxdh, VXGE_HW_RXD_STATE_POSTED,
				channel->userdata);

		vxge_hw_channel_dtr_free(channel, rxdh);
	}

	return VXGE_HW_OK;
}

/*
 * __vxge_hw_ring_reset - Resets the ring
 * This function resets the ring during vpath reset operation
 */
enum vxge_hw_status __vxge_hw_ring_reset(struct __vxge_hw_ring *ring)
{
	enum vxge_hw_status status = VXGE_HW_OK;
	struct __vxge_hw_channel *channel;

	channel = &ring->channel;

	__vxge_hw_ring_abort(ring);

	status = __vxge_hw_channel_reset(channel);

	if (status != VXGE_HW_OK)
		goto exit;

	if ((ring->lro_enable) && (ring->lro_enable != VXGE_HW_GRO_ENABLE)) {
		status = __vxge_hw_sw_lro_reset(ring);
		if (status != VXGE_HW_OK)
			goto exit;
	}

	if (ring->rxd_init) {
		status = vxge_hw_ring_replenish(ring);
		if (status != VXGE_HW_OK)
			goto exit;
	}
exit:
	return status;
}

/*
 * __vxge_hw_ring_delete - Removes the ring
 * This function freeup the memory pool and removes the ring
 */
enum vxge_hw_status __vxge_hw_ring_delete(struct __vxge_hw_vpath_handle *vp)
{
	struct __vxge_hw_ring *ring = vp->vpath->ringh;
	__vxge_hw_ring_abort(ring);

	if ((ring->lro_enable) && (ring->lro_enable != VXGE_HW_GRO_ENABLE))
		__vxge_hw_sw_lro_terminate(ring);

	if (ring->mempool)
		__vxge_hw_mempool_destroy(ring->mempool);

	vp->vpath->ringh = NULL;
	__vxge_hw_channel_free(&ring->channel);

	return VXGE_HW_OK;
}

/*
 * __vxge_hw_mempool_grow
 * Will resize mempool up to %num_allocate value.
 */
enum vxge_hw_status
__vxge_hw_mempool_grow(struct vxge_hw_mempool *mempool, u32 num_allocate,
		       u32 *num_allocated)
{
	u32 i, first_time = mempool->memblocks_allocated == 0 ? 1 : 0;
	u32 n_items = mempool->items_per_memblock;
	u32 start_block_idx = mempool->memblocks_allocated;
	u32 end_block_idx = mempool->memblocks_allocated + num_allocate;
	enum vxge_hw_status status = VXGE_HW_OK;

	*num_allocated = 0;

	if (end_block_idx > mempool->memblocks_max) {
		status = VXGE_HW_ERR_OUT_OF_MEMORY;
		goto exit;
	}

	for (i = start_block_idx; i < end_block_idx; i++) {
		u32 j;
		u32 is_last = ((end_block_idx - 1) == i);
		struct vxge_hw_mempool_dma *dma_object =
			mempool->memblocks_dma_arr + i;
		void *the_memblock;

		/* allocate memblock's private part. Each DMA memblock
		 * has a space allocated for item's private usage upon
		 * mempool's user request. Each time mempool grows, it will
		 * allocate new memblock and its private part at once.
		 * This helps to minimize memory usage a lot. */
		mempool->memblocks_priv_arr[i] =
				vmalloc(mempool->items_priv_size * n_items);
		if (mempool->memblocks_priv_arr[i] == NULL) {
			status = VXGE_HW_ERR_OUT_OF_MEMORY;
			goto exit;
		}

		memset(mempool->memblocks_priv_arr[i], 0,
			     mempool->items_priv_size * n_items);

		/* allocate DMA-capable memblock */
		mempool->memblocks_arr[i] =
			__vxge_hw_blockpool_malloc(mempool->devh,
				dma_object);
		if (mempool->memblocks_arr[i] == NULL) {
			vfree(mempool->memblocks_priv_arr[i]);
			status = VXGE_HW_ERR_OUT_OF_MEMORY;
			goto exit;
		}

		(*num_allocated)++;
		mempool->memblocks_allocated++;

		memset(mempool->memblocks_arr[i], 0, mempool->memblock_size);

		the_memblock = mempool->memblocks_arr[i];

		/* fill the items hash array */
		for (j = 0; j < n_items; j++) {
			u32 index = i * n_items + j;

			if (first_time && index >= mempool->items_initial)
				break;

			mempool->items_arr[index] =
				((char *)the_memblock + j*mempool->item_size);

			/* let caller to do more job on each item */
			if (mempool->item_func_alloc != NULL)
				mempool->item_func_alloc(mempool, i,
					dma_object, index, is_last);

			mempool->items_current = index + 1;
		}

		if (first_time && mempool->items_current ==
					mempool->items_initial)
			break;
	}
exit:
	return status;
}

/*
 * vxge_hw_mempool_create
 * This function will create memory pool object. Pool may grow but will
 * never shrink. Pool consists of number of dynamically allocated blocks
 * with size enough to hold %items_initial number of items. Memory is
 * DMA-able but client must map/unmap before interoperating with the device.
 */
struct vxge_hw_mempool*
__vxge_hw_mempool_create(
	struct __vxge_hw_device *devh,
	u32 memblock_size,
	u32 item_size,
	u32 items_priv_size,
	u32 items_initial,
	u32 items_max,
	struct vxge_hw_mempool_cbs *mp_callback,
	void *userdata)
{
	enum vxge_hw_status status = VXGE_HW_OK;
	u32 memblocks_to_allocate;
	struct vxge_hw_mempool *mempool = NULL;
	u32 allocated;

	if (memblock_size < item_size) {
		status = VXGE_HW_FAIL;
		goto exit;
	}

	mempool = (struct vxge_hw_mempool *)
			vmalloc(sizeof(struct vxge_hw_mempool));
	if (mempool == NULL) {
		status = VXGE_HW_ERR_OUT_OF_MEMORY;
		goto exit;
	}
	memset(mempool, 0, sizeof(struct vxge_hw_mempool));

	mempool->devh			= devh;
	mempool->memblock_size		= memblock_size;
	mempool->items_max		= items_max;
	mempool->items_initial		= items_initial;
	mempool->item_size		= item_size;
	mempool->items_priv_size	= items_priv_size;
	mempool->item_func_alloc	= mp_callback->item_func_alloc;
	mempool->userdata		= userdata;

	mempool->memblocks_allocated = 0;

	mempool->items_per_memblock = memblock_size / item_size;

	mempool->memblocks_max = (items_max + mempool->items_per_memblock - 1) /
					mempool->items_per_memblock;

	/* allocate array of memblocks */
	mempool->memblocks_arr =
		(void **) vmalloc(sizeof(void *) * mempool->memblocks_max);
	if (mempool->memblocks_arr == NULL) {
		__vxge_hw_mempool_destroy(mempool);
		status = VXGE_HW_ERR_OUT_OF_MEMORY;
		mempool = NULL;
		goto exit;
	}
	memset(mempool->memblocks_arr, 0,
		sizeof(void *) * mempool->memblocks_max);

	/* allocate array of private parts of items per memblocks */
	mempool->memblocks_priv_arr =
		(void **) vmalloc(sizeof(void *) * mempool->memblocks_max);
	if (mempool->memblocks_priv_arr == NULL) {
		__vxge_hw_mempool_destroy(mempool);
		status = VXGE_HW_ERR_OUT_OF_MEMORY;
		mempool = NULL;
		goto exit;
	}
	memset(mempool->memblocks_priv_arr, 0,
		    sizeof(void *) * mempool->memblocks_max);

	/* allocate array of memblocks DMA objects */
	mempool->memblocks_dma_arr = (struct vxge_hw_mempool_dma *)
		vmalloc(sizeof(struct vxge_hw_mempool_dma) *
			mempool->memblocks_max);

	if (mempool->memblocks_dma_arr == NULL) {
		__vxge_hw_mempool_destroy(mempool);
		status = VXGE_HW_ERR_OUT_OF_MEMORY;
		mempool = NULL;
		goto exit;
	}
	memset(mempool->memblocks_dma_arr, 0,
			sizeof(struct vxge_hw_mempool_dma) *
			mempool->memblocks_max);

	/* allocate hash array of items */
	mempool->items_arr =
		(void **) vmalloc(sizeof(void *) * mempool->items_max);
	if (mempool->items_arr == NULL) {
		__vxge_hw_mempool_destroy(mempool);
		status = VXGE_HW_ERR_OUT_OF_MEMORY;
		mempool = NULL;
		goto exit;
	}
	memset(mempool->items_arr, 0, sizeof(void *) * mempool->items_max);

	/* calculate initial number of memblocks */
	memblocks_to_allocate = (mempool->items_initial +
				 mempool->items_per_memblock - 1) /
						mempool->items_per_memblock;

	/* pre-allocate the mempool */
	status = __vxge_hw_mempool_grow(mempool, memblocks_to_allocate,
					&allocated);
	if (status != VXGE_HW_OK) {
		__vxge_hw_mempool_destroy(mempool);
		status = VXGE_HW_ERR_OUT_OF_MEMORY;
		mempool = NULL;
		goto exit;
	}

exit:
	return mempool;
}

/*
 * vxge_hw_mempool_destroy
 */
void __vxge_hw_mempool_destroy(struct vxge_hw_mempool *mempool)
{
	u32 i, j;
	struct __vxge_hw_device *devh = mempool->devh;

	for (i = 0; i < mempool->memblocks_allocated; i++) {
		struct vxge_hw_mempool_dma *dma_object;

		vxge_assert(mempool->memblocks_arr[i]);
		vxge_assert(mempool->memblocks_dma_arr + i);

		dma_object = mempool->memblocks_dma_arr + i;

		for (j = 0; j < mempool->items_per_memblock; j++) {
			u32 index = i * mempool->items_per_memblock + j;

			/* to skip last partially filled(if any) memblock */
			if (index >= mempool->items_current)
				break;
		}

		vfree(mempool->memblocks_priv_arr[i]);

		__vxge_hw_blockpool_free(devh, mempool->memblocks_arr[i],
				mempool->memblock_size, dma_object);
	}

	if (mempool->items_arr)
		vfree(mempool->items_arr);

	if (mempool->memblocks_dma_arr)
		vfree(mempool->memblocks_dma_arr);

	if (mempool->memblocks_priv_arr)
		vfree(mempool->memblocks_priv_arr);

	if (mempool->memblocks_arr)
		vfree(mempool->memblocks_arr);

	vfree(mempool);
}

/*
 * __vxge_hw_device_fifo_config_check - Check fifo configuration.
 * Check the fifo configuration
 */
enum vxge_hw_status
__vxge_hw_device_fifo_config_check(struct vxge_hw_fifo_config *fifo_config)
{
	if ((fifo_config->fifo_blocks < VXGE_HW_MIN_FIFO_BLOCKS) ||
	     (fifo_config->fifo_blocks > VXGE_HW_MAX_FIFO_BLOCKS))
		return VXGE_HW_BADCFG_FIFO_BLOCKS;

	return VXGE_HW_OK;
}

/*
 * __vxge_hw_device_vpath_config_check - Check vpath configuration.
 * Check the vpath configuration
 */
enum vxge_hw_status
__vxge_hw_device_vpath_config_check(struct vxge_hw_vp_config *vp_config)
{
	enum vxge_hw_status status;

	if ((vp_config->rx_bw_limit !=
		VXGE_HW_VPATH_RX_BW_LIMIT_DEFAULT) &&
		((vp_config->rx_bw_limit <
			VXGE_HW_VPATH_RX_BW_LIMIT_MIN) ||
		(vp_config->rx_bw_limit >
			VXGE_HW_VPATH_RX_BW_LIMIT_MAX)))
		return VXGE_HW_BADCFG_VPATH_MIN_BANDWIDTH;

	if ((vp_config->tx_bw_limit !=
		VXGE_HW_VPATH_TX_BW_LIMIT_DEFAULT) &&
		((vp_config->tx_bw_limit <
			VXGE_HW_VPATH_TX_BW_LIMIT_MIN) ||
		(vp_config->tx_bw_limit >
			VXGE_HW_VPATH_TX_BW_LIMIT_MAX)))
		return VXGE_HW_BADCFG_VPATH_BANDWIDTH_LIMIT;

	if ((vp_config->vp_prio != VXGE_HW_VPATH_PRIORITY_DEFAULT) &&
		((vp_config->vp_prio < VXGE_HW_VPATH_PRIORITY_HIGH) ||
		(vp_config->vp_prio > VXGE_HW_VPATH_PRIORITY_LOW)))
		return VXGE_HW_BADCFG_VPATH_PRIORITY;

	status = __vxge_hw_device_fifo_config_check(&vp_config->fifo);
	if (status != VXGE_HW_OK)
		return status;

	if ((vp_config->mtu != VXGE_HW_VPATH_USE_FLASH_DEFAULT_INITIAL_MTU) &&
		((vp_config->mtu < VXGE_HW_VPATH_MIN_INITIAL_MTU) ||
		(vp_config->mtu > VXGE_HW_VPATH_MAX_INITIAL_MTU)))
		return VXGE_HW_BADCFG_VPATH_MTU;

	if ((vp_config->rpa_strip_vlan_tag !=
		VXGE_HW_VPATH_RPA_STRIP_VLAN_TAG_USE_FLASH_DEFAULT) &&
		(vp_config->rpa_strip_vlan_tag !=
		VXGE_HW_VPATH_RPA_STRIP_VLAN_TAG_ENABLE) &&
		(vp_config->rpa_strip_vlan_tag !=
		VXGE_HW_VPATH_RPA_STRIP_VLAN_TAG_DISABLE))
		return VXGE_HW_BADCFG_VPATH_RPA_STRIP_VLAN_TAG;

	if ((vp_config->aggr_ack != VXGE_HW_VPATH_AGGR_ACK_ENABLE) &&
		(vp_config->aggr_ack != VXGE_HW_VPATH_AGGR_ACK_DISABLE) &&
		(vp_config->aggr_ack != VXGE_HW_VPATH_AGGR_ACK_DEFAULT))
		return VXGE_HW_BADCFG_VPATH_AGGR_ACK;

	return VXGE_HW_OK;
}

/*
 * __vxge_hw_device_config_check - Check device configuration.
 * Check the device configuration
 */
enum vxge_hw_status
__vxge_hw_device_config_check(struct vxge_hw_device_config *new_config)
{
	u32 i;
	enum vxge_hw_status status;

	if (

	(new_config->intr_mode != VXGE_HW_INTR_MODE_IRQLINE) &&
	   (new_config->intr_mode != VXGE_HW_INTR_MODE_MSIX) &&
	   (new_config->intr_mode != VXGE_HW_INTR_MODE_MSIX_ONE_SHOT) &&
	   (new_config->intr_mode != VXGE_HW_INTR_MODE_DEF))
		return VXGE_HW_BADCFG_INTR_MODE;

	for (i = 0; i < VXGE_HW_MAX_VIRTUAL_PATHS; i++) {
		status = __vxge_hw_device_vpath_config_check(
				&new_config->vp_config[i]);
		if (status != VXGE_HW_OK)
			return status;
	}

	return VXGE_HW_OK;
}

/*
 * vxge_hw_device_config_default_get - Initialize device config with defaults.
 * Initialize Titan device config with default values.
 */
enum vxge_hw_status __devinit
vxge_hw_device_config_default_get(struct vxge_hw_device_config *device_config)
{
	u32 i;

	device_config->intr_mode = VXGE_HW_INTR_MODE_DEF;
	device_config->rth_en = VXGE_HW_RTH_DEFAULT;
	device_config->rth_it_type = VXGE_HW_RTH_IT_TYPE_DEFAULT;
	device_config->device_poll_millis =  VXGE_HW_DEF_DEVICE_POLL_MILLIS;

	for (i = 0; i < VXGE_HW_MAX_VIRTUAL_PATHS; i++) {

		device_config->vp_config[i].vp_id = i;

		device_config->vp_config[i].rx_bw_limit =
				VXGE_HW_VPATH_RX_BW_LIMIT_DEFAULT;

		device_config->vp_config[i].tx_bw_limit =
				VXGE_HW_VPATH_TX_BW_LIMIT_DEFAULT;

		device_config->vp_config[i].vp_prio =
				VXGE_HW_VPATH_PRIORITY_DEFAULT;

		device_config->vp_config[i].ring.enable = VXGE_HW_RING_DEFAULT;

		device_config->vp_config[i].ring.ring_blocks =
				VXGE_HW_DEF_RING_BLOCKS;

		device_config->vp_config[i].ring.buffer_mode =
				VXGE_HW_RING_RXD_BUFFER_MODE_DEFAULT;

		device_config->vp_config[i].ring.scatter_mode =
				VXGE_HW_RING_SCATTER_MODE_USE_FLASH_DEFAULT;
		device_config->vp_config[i].ring.rxd_qword_limit =
				VXGE_HW_DEF_RING_RXD_QWORD_LIMIT;

		device_config->vp_config[i].fifo.enable = VXGE_HW_FIFO_ENABLE;

		device_config->vp_config[i].fifo.fifo_blocks =
				VXGE_HW_MIN_FIFO_BLOCKS;

		device_config->vp_config[i].fifo.max_frags =
				VXGE_HW_MAX_FIFO_FRAGS;

		device_config->vp_config[i].fifo.memblock_size =
				VXGE_HW_DEF_FIFO_MEMBLOCK_SIZE;

		device_config->vp_config[i].fifo.alignment_size =
				VXGE_HW_DEF_FIFO_ALIGNMENT_SIZE;

		device_config->vp_config[i].fifo.intr =
				VXGE_HW_FIFO_QUEUE_INTR_DEFAULT;

		device_config->vp_config[i].fifo.no_snoop_bits =
				VXGE_HW_FIFO_NO_SNOOP_DEFAULT;
		device_config->vp_config[i].tti.intr_enable =
				VXGE_HW_TIM_INTR_DEFAULT;

		device_config->vp_config[i].tti.btimer_val =
				VXGE_HW_USE_FLASH_DEFAULT;

		device_config->vp_config[i].tti.timer_ac_en =
				VXGE_HW_USE_FLASH_DEFAULT;

		device_config->vp_config[i].tti.timer_ci_en =
				VXGE_HW_USE_FLASH_DEFAULT;

		device_config->vp_config[i].tti.timer_ri_en =
				VXGE_HW_USE_FLASH_DEFAULT;

		device_config->vp_config[i].tti.rtimer_val =
				VXGE_HW_USE_FLASH_DEFAULT;

		device_config->vp_config[i].tti.util_sel =
				VXGE_HW_USE_FLASH_DEFAULT;

		device_config->vp_config[i].tti.ltimer_val =
				VXGE_HW_USE_FLASH_DEFAULT;

		device_config->vp_config[i].tti.urange_a =
				VXGE_HW_USE_FLASH_DEFAULT;

		device_config->vp_config[i].tti.uec_a =
				VXGE_HW_USE_FLASH_DEFAULT;

		device_config->vp_config[i].tti.urange_b =
				VXGE_HW_USE_FLASH_DEFAULT;

		device_config->vp_config[i].tti.uec_b =
				VXGE_HW_USE_FLASH_DEFAULT;

		device_config->vp_config[i].tti.urange_c =
				VXGE_HW_USE_FLASH_DEFAULT;

		device_config->vp_config[i].tti.uec_c =
				VXGE_HW_USE_FLASH_DEFAULT;

		device_config->vp_config[i].tti.uec_d =
				VXGE_HW_USE_FLASH_DEFAULT;

		device_config->vp_config[i].rti.intr_enable =
				VXGE_HW_TIM_INTR_DEFAULT;

		device_config->vp_config[i].rti.btimer_val =
				VXGE_HW_USE_FLASH_DEFAULT;

		device_config->vp_config[i].rti.timer_ac_en =
				VXGE_HW_USE_FLASH_DEFAULT;

		device_config->vp_config[i].rti.timer_ci_en =
				VXGE_HW_USE_FLASH_DEFAULT;

		device_config->vp_config[i].rti.timer_ri_en =
				VXGE_HW_USE_FLASH_DEFAULT;

		device_config->vp_config[i].rti.rtimer_val =
				VXGE_HW_USE_FLASH_DEFAULT;

		device_config->vp_config[i].rti.util_sel =
				VXGE_HW_USE_FLASH_DEFAULT;

		device_config->vp_config[i].rti.ltimer_val =
				VXGE_HW_USE_FLASH_DEFAULT;

		device_config->vp_config[i].rti.urange_a =
				VXGE_HW_USE_FLASH_DEFAULT;

		device_config->vp_config[i].rti.uec_a =
				VXGE_HW_USE_FLASH_DEFAULT;

		device_config->vp_config[i].rti.urange_b =
				VXGE_HW_USE_FLASH_DEFAULT;

		device_config->vp_config[i].rti.uec_b =
				VXGE_HW_USE_FLASH_DEFAULT;

		device_config->vp_config[i].rti.urange_c =
				VXGE_HW_USE_FLASH_DEFAULT;

		device_config->vp_config[i].rti.uec_c =
				VXGE_HW_USE_FLASH_DEFAULT;

		device_config->vp_config[i].rti.uec_d =
				VXGE_HW_USE_FLASH_DEFAULT;

		device_config->vp_config[i].mtu =
				VXGE_HW_VPATH_USE_FLASH_DEFAULT_INITIAL_MTU;

		device_config->vp_config[i].rpa_strip_vlan_tag =
			VXGE_HW_VPATH_RPA_STRIP_VLAN_TAG_USE_FLASH_DEFAULT;

		device_config->vp_config[i].aggr_ack =
				VXGE_HW_VPATH_AGGR_ACK_DEFAULT;
	}
	device_config->stats_read_method = VXGE_HW_STATS_READ_METHOD_DEFAULT;

	return VXGE_HW_OK;
}

/*
 * _hw_legacy_swapper_set - Set the swapper bits for the legacy secion.
 * Set the swapper bits appropriately for the legacy section.
 */
enum vxge_hw_status
__vxge_hw_legacy_swapper_set(struct vxge_hw_legacy_reg __iomem *legacy_reg)
{
	u64 val64;
	enum vxge_hw_status status = VXGE_HW_OK;

	val64 = readq(&legacy_reg->toc_swapper_fb);

	wmb();

	switch (val64) {

	case VXGE_HW_SWAPPER_INITIAL_VALUE:
		return status;

	case VXGE_HW_SWAPPER_BYTE_SWAPPED_BIT_FLIPPED:
		writeq(VXGE_HW_SWAPPER_READ_BYTE_SWAP_ENABLE,
			&legacy_reg->pifm_rd_swap_en);
		writeq(VXGE_HW_SWAPPER_READ_BIT_FLAP_ENABLE,
			&legacy_reg->pifm_rd_flip_en);
		writeq(VXGE_HW_SWAPPER_WRITE_BYTE_SWAP_ENABLE,
			&legacy_reg->pifm_wr_swap_en);
		writeq(VXGE_HW_SWAPPER_WRITE_BIT_FLAP_ENABLE,
			&legacy_reg->pifm_wr_flip_en);
		break;

	case VXGE_HW_SWAPPER_BYTE_SWAPPED:
		writeq(VXGE_HW_SWAPPER_READ_BYTE_SWAP_ENABLE,
			&legacy_reg->pifm_rd_swap_en);
		writeq(VXGE_HW_SWAPPER_WRITE_BYTE_SWAP_ENABLE,
			&legacy_reg->pifm_wr_swap_en);
		break;

	case VXGE_HW_SWAPPER_BIT_FLIPPED:
		writeq(VXGE_HW_SWAPPER_READ_BIT_FLAP_ENABLE,
			&legacy_reg->pifm_rd_flip_en);
		writeq(VXGE_HW_SWAPPER_WRITE_BIT_FLAP_ENABLE,
			&legacy_reg->pifm_wr_flip_en);
		break;
	}

	wmb();

	val64 = readq(&legacy_reg->toc_swapper_fb);

	if (val64 != VXGE_HW_SWAPPER_INITIAL_VALUE)
		status = VXGE_HW_ERR_SWAPPER_CTRL;

	return status;
}

/*
 * __vxge_hw_vpath_swapper_set - Set the swapper bits for the vpath.
 * Set the swapper bits appropriately for the vpath.
 */
enum vxge_hw_status
__vxge_hw_vpath_swapper_set(struct vxge_hw_vpath_reg __iomem *vpath_reg)
{
#ifndef __BIG_ENDIAN
	u64 val64;

	val64 = readq(&vpath_reg->vpath_general_cfg1);
	wmb();
	val64 |= VXGE_HW_VPATH_GENERAL_CFG1_CTL_BYTE_SWAPEN;
	writeq(val64, &vpath_reg->vpath_general_cfg1);
	wmb();
#endif
	return VXGE_HW_OK;
}

/*
 * __vxge_hw_kdfc_swapper_set - Set the swapper bits for the kdfc.
 * Set the swapper bits appropriately for the vpath.
 */
enum vxge_hw_status
__vxge_hw_kdfc_swapper_set(
	struct vxge_hw_legacy_reg __iomem *legacy_reg,
	struct vxge_hw_vpath_reg __iomem *vpath_reg)
{
	u64 val64;

	val64 = readq(&legacy_reg->pifm_wr_swap_en);

	if (val64 == VXGE_HW_SWAPPER_WRITE_BYTE_SWAP_ENABLE) {
		val64 = readq(&vpath_reg->kdfcctl_cfg0);
		wmb();

		val64 |= VXGE_HW_KDFCCTL_CFG0_BYTE_SWAPEN_FIFO0	|
			VXGE_HW_KDFCCTL_CFG0_BYTE_SWAPEN_FIFO1	|
			VXGE_HW_KDFCCTL_CFG0_BYTE_SWAPEN_FIFO2;

		writeq(val64, &vpath_reg->kdfcctl_cfg0);
		wmb();
	}

	return VXGE_HW_OK;
}

/*
 * vxge_hw_mgmt_device_config - Retrieve device configuration.
 * Get device configuration. Permits to retrieve at run-time configuration
 * values that were used to initialize and configure the device.
 */
enum vxge_hw_status
vxge_hw_mgmt_device_config(struct __vxge_hw_device *hldev,
			   struct vxge_hw_device_config *dev_config, int size)
{

	if ((hldev == NULL) || (hldev->magic != VXGE_HW_DEVICE_MAGIC))
		return VXGE_HW_ERR_INVALID_DEVICE;

	if (size != sizeof(struct vxge_hw_device_config))
		return VXGE_HW_ERR_VERSION_CONFLICT;

	memcpy(dev_config, &hldev->config,
		sizeof(struct vxge_hw_device_config));

	return VXGE_HW_OK;
}

/*
 * vxge_hw_mgmt_reg_read - Read Titan register.
 */
enum vxge_hw_status
vxge_hw_mgmt_reg_read(struct __vxge_hw_device *hldev,
		      enum vxge_hw_mgmt_reg_type type,
		      u32 index, u32 offset, u64 *value)
{
	enum vxge_hw_status status = VXGE_HW_OK;

	if ((hldev == NULL) || (hldev->magic != VXGE_HW_DEVICE_MAGIC)) {
		status = VXGE_HW_ERR_INVALID_DEVICE;
		goto exit;
	}

	switch (type) {
	case vxge_hw_mgmt_reg_type_legacy:
		if (offset > sizeof(struct vxge_hw_legacy_reg) - 8) {
			status = VXGE_HW_ERR_INVALID_OFFSET;
			break;
		}
		*value = readq((void __iomem *)hldev->legacy_reg + offset);
		break;
	case vxge_hw_mgmt_reg_type_toc:
		if (offset > sizeof(struct vxge_hw_toc_reg) - 8) {
			status = VXGE_HW_ERR_INVALID_OFFSET;
			break;
		}
		*value = readq((void __iomem *)hldev->toc_reg + offset);
		break;
	case vxge_hw_mgmt_reg_type_common:
		if (offset > sizeof(struct vxge_hw_common_reg) - 8) {
			status = VXGE_HW_ERR_INVALID_OFFSET;
			break;
		}
		*value = readq((void __iomem *)hldev->common_reg + offset);
		break;
	case vxge_hw_mgmt_reg_type_mrpcim:
		if (!(hldev->access_rights &
			VXGE_HW_DEVICE_ACCESS_RIGHT_MRPCIM)) {
			status = VXGE_HW_ERR_PRIVILAGED_OPEARATION;
			break;
		}
		if (offset > sizeof(struct vxge_hw_mrpcim_reg) - 8) {
			status = VXGE_HW_ERR_INVALID_OFFSET;
			break;
		}
		*value = readq((void __iomem *)hldev->mrpcim_reg + offset);
		break;
	case vxge_hw_mgmt_reg_type_srpcim:
		if (!(hldev->access_rights &
			VXGE_HW_DEVICE_ACCESS_RIGHT_SRPCIM)) {
			status = VXGE_HW_ERR_PRIVILAGED_OPEARATION;
			break;
		}
		if (index > VXGE_HW_TITAN_SRPCIM_REG_SPACES - 1) {
			status = VXGE_HW_ERR_INVALID_INDEX;
			break;
		}
		if (offset > sizeof(struct vxge_hw_srpcim_reg) - 8) {
			status = VXGE_HW_ERR_INVALID_OFFSET;
			break;
		}
		*value = readq((void __iomem *)hldev->srpcim_reg[index] +
				offset);
		break;
	case vxge_hw_mgmt_reg_type_vpmgmt:
		if ((index > VXGE_HW_TITAN_VPMGMT_REG_SPACES - 1) ||
			(!(hldev->vpath_assignments & vxge_mBIT(index)))) {
			status = VXGE_HW_ERR_INVALID_INDEX;
			break;
		}
		if (offset > sizeof(struct vxge_hw_vpmgmt_reg) - 8) {
			status = VXGE_HW_ERR_INVALID_OFFSET;
			break;
		}
		*value = readq((void __iomem *)hldev->vpmgmt_reg[index] +
				offset);
		break;
	case vxge_hw_mgmt_reg_type_vpath:
		if ((index > VXGE_HW_TITAN_VPATH_REG_SPACES - 1) ||
			(!(hldev->vpath_assignments & vxge_mBIT(index)))) {
			status = VXGE_HW_ERR_INVALID_INDEX;
			break;
		}
		if (index > VXGE_HW_TITAN_VPATH_REG_SPACES - 1) {
			status = VXGE_HW_ERR_INVALID_INDEX;
			break;
		}
		if (offset > sizeof(struct vxge_hw_vpath_reg) - 8) {
			status = VXGE_HW_ERR_INVALID_OFFSET;
			break;
		}
		*value = readq((void __iomem *)hldev->vpath_reg[index] +
				offset);
		break;
	default:
		status = VXGE_HW_ERR_INVALID_TYPE;
		break;
	}

exit:
	return status;
}

/*
 * vxge_hw_vpath_strip_fcs_check - Check for FCS strip.
 */
enum vxge_hw_status
vxge_hw_vpath_strip_fcs_check(struct __vxge_hw_device *hldev, u64 vpath_mask)
{
	struct vxge_hw_vpmgmt_reg __iomem *vpmgmt_reg;
	enum vxge_hw_status status = VXGE_HW_OK;
	int i = 0, j = 0;

	for (i = 0; i < VXGE_HW_MAX_VIRTUAL_PATHS; i++) {
		if (!((vpath_mask) & vxge_mBIT(i)))
			continue;
		vpmgmt_reg = hldev->vpmgmt_reg[i];
		for (j = 0; j < VXGE_HW_MAC_MAX_MAC_PORT_ID; j++) {
			if (readq(&vpmgmt_reg->rxmac_cfg0_port_vpmgmt_clone[j])
			& VXGE_HW_RXMAC_CFG0_PORT_VPMGMT_CLONE_STRIP_FCS)
				return VXGE_HW_FAIL;
		}
	}
	return status;
}

/*
 * vxge_hw_mgmt_reg_Write - Write Titan register.
 */
enum vxge_hw_status
vxge_hw_mgmt_reg_write(struct __vxge_hw_device *hldev,
		      enum vxge_hw_mgmt_reg_type type,
		      u32 index, u32 offset, u64 value)
{
	enum vxge_hw_status status = VXGE_HW_OK;

	if ((hldev == NULL) || (hldev->magic != VXGE_HW_DEVICE_MAGIC)) {
		status = VXGE_HW_ERR_INVALID_DEVICE;
		goto exit;
	}

	switch (type) {
	case vxge_hw_mgmt_reg_type_legacy:
		if (offset > sizeof(struct vxge_hw_legacy_reg) - 8) {
			status = VXGE_HW_ERR_INVALID_OFFSET;
			break;
		}
		writeq(value, (void __iomem *)hldev->legacy_reg + offset);
		break;
	case vxge_hw_mgmt_reg_type_toc:
		if (offset > sizeof(struct vxge_hw_toc_reg) - 8) {
			status = VXGE_HW_ERR_INVALID_OFFSET;
			break;
		}
		writeq(value, (void __iomem *)hldev->toc_reg + offset);
		break;
	case vxge_hw_mgmt_reg_type_common:
		if (offset > sizeof(struct vxge_hw_common_reg) - 8) {
			status = VXGE_HW_ERR_INVALID_OFFSET;
			break;
		}
		writeq(value, (void __iomem *)hldev->common_reg + offset);
		break;
	case vxge_hw_mgmt_reg_type_mrpcim:
		if (!(hldev->access_rights &
			VXGE_HW_DEVICE_ACCESS_RIGHT_MRPCIM)) {
			status = VXGE_HW_ERR_PRIVILAGED_OPEARATION;
			break;
		}
		if (offset > sizeof(struct vxge_hw_mrpcim_reg) - 8) {
			status = VXGE_HW_ERR_INVALID_OFFSET;
			break;
		}
		writeq(value, (void __iomem *)hldev->mrpcim_reg + offset);
		break;
	case vxge_hw_mgmt_reg_type_srpcim:
		if (!(hldev->access_rights &
			VXGE_HW_DEVICE_ACCESS_RIGHT_SRPCIM)) {
			status = VXGE_HW_ERR_PRIVILAGED_OPEARATION;
			break;
		}
		if (index > VXGE_HW_TITAN_SRPCIM_REG_SPACES - 1) {
			status = VXGE_HW_ERR_INVALID_INDEX;
			break;
		}
		if (offset > sizeof(struct vxge_hw_srpcim_reg) - 8) {
			status = VXGE_HW_ERR_INVALID_OFFSET;
			break;
		}
		writeq(value, (void __iomem *)hldev->srpcim_reg[index] +
			offset);

		break;
	case vxge_hw_mgmt_reg_type_vpmgmt:
		if ((index > VXGE_HW_TITAN_VPMGMT_REG_SPACES - 1) ||
			(!(hldev->vpath_assignments & vxge_mBIT(index)))) {
			status = VXGE_HW_ERR_INVALID_INDEX;
			break;
		}
		if (offset > sizeof(struct vxge_hw_vpmgmt_reg) - 8) {
			status = VXGE_HW_ERR_INVALID_OFFSET;
			break;
		}
		writeq(value, (void __iomem *)hldev->vpmgmt_reg[index] +
			offset);
		break;
	case vxge_hw_mgmt_reg_type_vpath:
		if ((index > VXGE_HW_TITAN_VPATH_REG_SPACES-1) ||
			(!(hldev->vpath_assignments & vxge_mBIT(index)))) {
			status = VXGE_HW_ERR_INVALID_INDEX;
			break;
		}
		if (offset > sizeof(struct vxge_hw_vpath_reg) - 8) {
			status = VXGE_HW_ERR_INVALID_OFFSET;
			break;
		}
		writeq(value, (void __iomem *)hldev->vpath_reg[index] +
			offset);
		break;
	default:
		status = VXGE_HW_ERR_INVALID_TYPE;
		break;
	}
exit:
	return status;
}

/*
 * __vxge_hw_fifo_mempool_item_alloc - Allocate List blocks for TxD
 * list callback
 * This function is callback passed to __vxge_hw_mempool_create to create memory
 * pool for TxD list
 */
static void
__vxge_hw_fifo_mempool_item_alloc(
	struct vxge_hw_mempool *mempoolh,
	u32 memblock_index, struct vxge_hw_mempool_dma *dma_object,
	u32 index, u32 is_last)
{
	u32 memblock_item_idx;

	struct __vxge_hw_fifo_txdl_priv *txdl_priv;
	struct vxge_hw_fifo_txd *txdp =
		(struct vxge_hw_fifo_txd *)mempoolh->items_arr[index];
	struct __vxge_hw_fifo *fifo =
			(struct __vxge_hw_fifo *)mempoolh->userdata;
	void *memblock = mempoolh->memblocks_arr[memblock_index];

	vxge_assert(txdp);

	txdp->host_control = (u64) (size_t)
	__vxge_hw_mempool_item_priv(mempoolh, memblock_index, txdp,
					&memblock_item_idx);

	txdl_priv = __vxge_hw_fifo_txdl_priv(fifo, txdp);

	vxge_assert(txdl_priv);

	fifo->channel.dtr_arr[fifo->channel.free_count - 1 - index] = txdp;

	/* pre-format HW's TxDL's private */
	txdl_priv->dma_offset = (char *)txdp - (char *)memblock;
	txdl_priv->dma_addr = dma_object->addr + txdl_priv->dma_offset;
	txdl_priv->dma_handle = dma_object->handle;
	txdl_priv->memblock   = memblock;
	txdl_priv->first_txdp = txdp;
	txdl_priv->next_txdl_priv = NULL;
	txdl_priv->alloc_frags = 0;

	return;
}

/*
 * __vxge_hw_fifo_create - Create a FIFO
 * This function creates FIFO and initializes it.
 */
enum vxge_hw_status
__vxge_hw_fifo_create(struct __vxge_hw_vpath_handle *vp,
		      struct vxge_hw_fifo_attr *attr)
{
	enum vxge_hw_status status = VXGE_HW_OK;
	struct __vxge_hw_fifo *fifo;
	struct vxge_hw_fifo_config *config;
	u32 txdl_size, txdl_per_memblock;
	struct vxge_hw_mempool_cbs fifo_mp_callback;
	struct __vxge_hw_virtualpath *vpath;

	if ((vp == NULL) || (attr == NULL)) {
		status = VXGE_HW_ERR_INVALID_HANDLE;
		goto exit;
	}
	vpath = vp->vpath;
	config = &vpath->hldev->config.vp_config[vpath->vp_id].fifo;

	txdl_size = config->max_frags * sizeof(struct vxge_hw_fifo_txd);

	txdl_per_memblock = config->memblock_size / txdl_size;

	fifo = (struct __vxge_hw_fifo *)__vxge_hw_channel_allocate(vp,
					VXGE_HW_CHANNEL_TYPE_FIFO,
					config->fifo_blocks * txdl_per_memblock,
					attr->per_txdl_space, attr->userdata);

	if (fifo == NULL) {
		status = VXGE_HW_ERR_OUT_OF_MEMORY;
		goto exit;
	}

	vpath->fifoh = fifo;
	fifo->nofl_db = vpath->nofl_db;

	fifo->vp_id = vpath->vp_id;
	fifo->vp_reg = vpath->vp_reg;
	fifo->stats = &vpath->sw_stats->fifo_stats;

	fifo->config = config;
	fifo->vp_config = &vpath->hldev->config.vp_config[vpath->vp_id];

	/* apply "interrupts per txdl" attribute */
	fifo->interrupt_type = VXGE_HW_FIFO_TXD_INT_TYPE_UTILZ;

	fifo->tim_tti_cfg1_saved = vpath->tim_tti_cfg1_saved;
	fifo->tim_tti_cfg3_saved = vpath->tim_tti_cfg3_saved;

	if (fifo->config->intr)
		fifo->interrupt_type = VXGE_HW_FIFO_TXD_INT_TYPE_PER_LIST;

	fifo->no_snoop_bits = config->no_snoop_bits;

	/*
	 * FIFO memory management strategy:
	 *
	 * TxDL split into three independent parts:
	 *	- set of TxD's
	 *	- TxD HW private part
	 *	- driver private part
	 *
	 * Adaptative memory allocation used. i.e. Memory allocated on
	 * demand with the size which will fit into one memory block.
	 * One memory block may contain more than one TxDL.
	 *
	 * During "reserve" operations more memory can be allocated on demand
	 * for example due to FIFO full condition.
	 *
	 * Pool of memory memblocks never shrinks except in __vxge_hw_fifo_close
	 * routine which will essentially stop the channel and free resources.
	 */

	/* TxDL common private size == TxDL private  +  driver private */
	fifo->priv_size =
		sizeof(struct __vxge_hw_fifo_txdl_priv) + attr->per_txdl_space;
	fifo->priv_size = ((fifo->priv_size  +  VXGE_CACHE_LINE_SIZE - 1) /
			VXGE_CACHE_LINE_SIZE) * VXGE_CACHE_LINE_SIZE;

	fifo->per_txdl_space = attr->per_txdl_space;

	/* recompute txdl size to be cacheline aligned */
	fifo->txdl_size = txdl_size;
	fifo->txdl_per_memblock = txdl_per_memblock;

	fifo->txdl_term = attr->txdl_term;
	fifo->callback = attr->callback;

	if (fifo->txdl_per_memblock == 0) {
		__vxge_hw_fifo_delete(vp);
		status = VXGE_HW_ERR_INVALID_BLOCK_SIZE;
		goto exit;
	}

	fifo_mp_callback.item_func_alloc = __vxge_hw_fifo_mempool_item_alloc;

	fifo->mempool =
		__vxge_hw_mempool_create(vpath->hldev,
			fifo->config->memblock_size,
			fifo->txdl_size,
			fifo->priv_size,
			(fifo->config->fifo_blocks * fifo->txdl_per_memblock),
			(fifo->config->fifo_blocks * fifo->txdl_per_memblock),
			&fifo_mp_callback,
			fifo);

	if (fifo->mempool == NULL) {
		__vxge_hw_fifo_delete(vp);
		status = VXGE_HW_ERR_OUT_OF_MEMORY;
		goto exit;
	}

	status = __vxge_hw_channel_initialize(&fifo->channel);
	if (status != VXGE_HW_OK) {
		__vxge_hw_fifo_delete(vp);
		goto exit;
	}

exit:
	return status;
}

/*
 * __vxge_hw_fifo_abort - Returns the TxD
 * This function terminates the TxDs of fifo
 */
enum vxge_hw_status __vxge_hw_fifo_abort(struct __vxge_hw_fifo *fifo)
{
	void *txdlh;

	for (;;) {
		vxge_hw_channel_dtr_try_complete(&fifo->channel, &txdlh);

		if (txdlh == NULL)
			break;

		vxge_hw_channel_dtr_complete(&fifo->channel);

		if (fifo->txdl_term) {
			fifo->txdl_term(txdlh,
			VXGE_HW_TXDL_STATE_POSTED,
			fifo->channel.userdata);
		}

		vxge_hw_channel_dtr_free(&fifo->channel, txdlh);
	}

	return VXGE_HW_OK;
}

/*
 * __vxge_hw_fifo_reset - Resets the fifo
 * This function resets the fifo during vpath reset operation
 */
enum vxge_hw_status __vxge_hw_fifo_reset(struct __vxge_hw_fifo *fifo)
{
	enum vxge_hw_status status = VXGE_HW_OK;

	__vxge_hw_fifo_abort(fifo);
	status = __vxge_hw_channel_reset(&fifo->channel);

	return status;
}

/*
 * __vxge_hw_fifo_delete - Removes the FIFO
 * This function freeup the memory pool and removes the FIFO
 */
enum vxge_hw_status __vxge_hw_fifo_delete(struct __vxge_hw_vpath_handle *vp)
{
	struct __vxge_hw_fifo *fifo = vp->vpath->fifoh;

	__vxge_hw_fifo_abort(fifo);

	if (fifo->mempool)
		__vxge_hw_mempool_destroy(fifo->mempool);

	vp->vpath->fifoh = NULL;

	__vxge_hw_channel_free(&fifo->channel);

	return VXGE_HW_OK;
}

/*
 * __vxge_hw_vpath_pci_read - Read the content of given address
 *                          in pci config space.
 * Read from the vpath pci config space.
 */
enum vxge_hw_status
__vxge_hw_vpath_pci_read(struct __vxge_hw_virtualpath *vpath,
			 u32 phy_func_0, u32 offset, u32 *val)
{
	u64 val64;
	enum vxge_hw_status status = VXGE_HW_OK;
	struct vxge_hw_vpath_reg __iomem *vp_reg = vpath->vp_reg;

	val64 =	VXGE_HW_PCI_CONFIG_ACCESS_CFG1_ADDRESS(offset);

	if (phy_func_0)
		val64 |= VXGE_HW_PCI_CONFIG_ACCESS_CFG1_SEL_FUNC0;

	writeq(val64, &vp_reg->pci_config_access_cfg1);
	wmb();
	writeq(VXGE_HW_PCI_CONFIG_ACCESS_CFG2_REQ,
			&vp_reg->pci_config_access_cfg2);
	wmb();

	status = __vxge_hw_device_register_poll(
			&vp_reg->pci_config_access_cfg2,
			VXGE_HW_INTR_MASK_ALL, VXGE_HW_DEF_DEVICE_POLL_MILLIS);

	if (status != VXGE_HW_OK)
		goto exit;

	val64 = readq(&vp_reg->pci_config_access_status);

	if (val64 & VXGE_HW_PCI_CONFIG_ACCESS_STATUS_ACCESS_ERR) {
		status = VXGE_HW_FAIL;
		*val = 0;
	} else
		*val = (u32)vxge_bVALn(val64, 32, 32);
exit:
	return status;
}

/*
 * __vxge_hw_vpath_func_id_get - Get the function id of the vpath.
 * Returns the function number of the vpath.
 */
u32
__vxge_hw_vpath_func_id_get(u32 vp_id,
	struct vxge_hw_vpmgmt_reg __iomem *vpmgmt_reg)
{
	u64 val64;

	val64 = readq(&vpmgmt_reg->vpath_to_func_map_cfg1);

	return
	 (u32)VXGE_HW_VPATH_TO_FUNC_MAP_CFG1_GET_VPATH_TO_FUNC_MAP_CFG1(val64);
}

/*
 * __vxge_hw_read_rts_ds - Program RTS steering critieria
 */
static inline void
__vxge_hw_read_rts_ds(struct vxge_hw_vpath_reg __iomem *vpath_reg,
		      u64 dta_struct_sel)
{
	writeq(0, &vpath_reg->rts_access_steer_ctrl);
	wmb();
	writeq(dta_struct_sel, &vpath_reg->rts_access_steer_data0);
	writeq(0, &vpath_reg->rts_access_steer_data1);
	wmb();
	return;
}

enum vxge_hw_status
__vxge_hw_get_port_cnt(struct __vxge_hw_device *hldev, u32 *ports)
{
	u64 data1 = VXGE_HW_RTS_ACCESS_STEER_DATA0_MEMO_ITEM_PORTS;
	u64 data2 = 0ULL, steer_ctrl = 0x0;
	enum vxge_hw_status status = VXGE_HW_OK;
	u32 fw_memo = VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL_FW_MEMO;
	*ports = 1;

	status = vxge_hw_vpath_fw_api(hldev, hldev->first_vp_id,
	    VXGE_HW_RTS_ACCESS_STEER_CTRL_ACTION_READ_MEMO_ENTRY,
	    0, fw_memo, &data1, &data2, &steer_ctrl);

	if (status == VXGE_HW_OK)
		*ports = (u32)data1;

	return status;
}

/*
 * __vxge_hw_vpath_pmd_info_get - Get the PMD info
 * @hldev: hardware device handle
 * @vp_id: vpath id
 * @ports: Number of ports supported
 * @pmd_port0: Buffer to return PMD info for port 0
 * @pmd_port1: Buffer to return PMD info for port 1
 *
 * Returns PMD Info
 *
 */
enum vxge_hw_status
__vxge_hw_vpath_pmd_info_get(struct __vxge_hw_device *hldev,
	u64 vp_id,
	u32 *ports,
	struct vxge_hw_device_pmd_info *pmd_port0,
	struct vxge_hw_device_pmd_info *pmd_port1)
{
	u64 data1 = 0ULL;
	u64 data2 = 0ULL, steer_ctrl = 0ULL;
	enum vxge_hw_status status = VXGE_HW_OK;
	u32 fw_memo = VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL_FW_MEMO;

	data1 = VXGE_HW_RTS_ACCESS_STEER_DATA0_MEMO_ITEM_PORTS;
	status = vxge_hw_vpath_fw_api(hldev, vp_id,
	    VXGE_HW_RTS_ACCESS_STEER_CTRL_ACTION_READ_MEMO_ENTRY,
	    0, fw_memo, &data1, &data2, &steer_ctrl);

	if (status != VXGE_HW_OK)
		return status;

	*ports = (u32)data1;

	data1 = VXGE_HW_RTS_ACCESS_STEER_DATA0_MEMO_ITEM_PORT0_PMD_TYPE;
	status = vxge_hw_vpath_fw_api(hldev, vp_id,
	    VXGE_HW_RTS_ACCESS_STEER_CTRL_ACTION_READ_MEMO_ENTRY,
	    0, fw_memo, &data1, &data2, &steer_ctrl);

	if (status != VXGE_HW_OK)
		return status;

	if (data1) {
		pmd_port0->type = (u32)data1;
		data1 = VXGE_HW_RTS_ACCESS_STEER_DATA0_MEMO_ITEM_PORT0_PMD_VENDOR;
		status = vxge_hw_vpath_fw_api(hldev, vp_id,
		    VXGE_HW_RTS_ACCESS_STEER_CTRL_ACTION_READ_MEMO_ENTRY,
		    0, fw_memo, &data1, &data2, &steer_ctrl);

		if (status != VXGE_HW_OK)
			return status;

		((u64 *)pmd_port0->vendor)[0] = be64_to_cpu(data1);
		((u64 *)pmd_port0->vendor)[1] = be64_to_cpu(data2);

		data1 = VXGE_HW_RTS_ACCESS_STEER_DATA0_MEMO_ITEM_PORT0_PMD_PARTNO;
		status = vxge_hw_vpath_fw_api(hldev, vp_id,
		    VXGE_HW_RTS_ACCESS_STEER_CTRL_ACTION_READ_MEMO_ENTRY,
		    0, fw_memo, &data1, &data2, &steer_ctrl);

		if (status != VXGE_HW_OK)
			return status;

		((u64 *)pmd_port0->part_num)[0] = be64_to_cpu(data1);
		((u64 *)pmd_port0->part_num)[1] = be64_to_cpu(data2);

		data1 = VXGE_HW_RTS_ACCESS_STEER_DATA0_MEMO_ITEM_PORT0_PMD_SERNO;
		status = vxge_hw_vpath_fw_api(hldev, vp_id,
		    VXGE_HW_RTS_ACCESS_STEER_CTRL_ACTION_READ_MEMO_ENTRY,
		    0, fw_memo, &data1, &data2, &steer_ctrl);

		if (status != VXGE_HW_OK)
			return status;

		((u64 *)pmd_port0->ser_num)[0] = be64_to_cpu(data1);
		((u64 *)pmd_port0->ser_num)[1] = be64_to_cpu(data2);
	} else
		memset(pmd_port0, 0, sizeof(struct vxge_hw_device_pmd_info));

	data1 = VXGE_HW_RTS_ACCESS_STEER_DATA0_MEMO_ITEM_PORT1_PMD_TYPE;
	status = vxge_hw_vpath_fw_api(hldev, vp_id,
	    VXGE_HW_RTS_ACCESS_STEER_CTRL_ACTION_READ_MEMO_ENTRY,
	    0, fw_memo, &data1, &data2, &steer_ctrl);

	if (status != VXGE_HW_OK)
		return status;

	if (data1) {
		pmd_port1->type = (u32)data1;
		data1 = VXGE_HW_RTS_ACCESS_STEER_DATA0_MEMO_ITEM_PORT1_PMD_VENDOR;
		status = vxge_hw_vpath_fw_api(hldev, vp_id,
		    VXGE_HW_RTS_ACCESS_STEER_CTRL_ACTION_READ_MEMO_ENTRY,
		    0, fw_memo, &data1, &data2, &steer_ctrl);

		if (status != VXGE_HW_OK)
			return status;

		((u64 *)pmd_port1->vendor)[0] = be64_to_cpu(data1);
		((u64 *)pmd_port1->vendor)[1] = be64_to_cpu(data2);

		data1 = VXGE_HW_RTS_ACCESS_STEER_DATA0_MEMO_ITEM_PORT1_PMD_PARTNO;
		status = vxge_hw_vpath_fw_api(hldev, vp_id,
		    VXGE_HW_RTS_ACCESS_STEER_CTRL_ACTION_READ_MEMO_ENTRY,
		    0, fw_memo, &data1, &data2, &steer_ctrl);

		if (status != VXGE_HW_OK)
			return status;

		((u64 *)pmd_port1->part_num)[0] = be64_to_cpu(data1);
		((u64 *)pmd_port1->part_num)[1] = be64_to_cpu(data2);

		data1 = VXGE_HW_RTS_ACCESS_STEER_DATA0_MEMO_ITEM_PORT1_PMD_SERNO;
		status = vxge_hw_vpath_fw_api(hldev, vp_id,
		    VXGE_HW_RTS_ACCESS_STEER_CTRL_ACTION_READ_MEMO_ENTRY,
		    0, fw_memo, &data1, &data2, &steer_ctrl);

		if (status != VXGE_HW_OK)
			return status;

		((u64 *)pmd_port1->ser_num)[0] = be64_to_cpu(data1);
		((u64 *)pmd_port1->ser_num)[1] = be64_to_cpu(data2);

	} else
		memset(pmd_port1, 0, sizeof(struct vxge_hw_device_pmd_info));

	return status;
}

/*
 * __vxge_hw_vpath_card_info_get - Get the serial numbers,
 * part number and product description.
 */
enum vxge_hw_status
__vxge_hw_vpath_card_info_get(
	u32 vp_id,
	struct vxge_hw_vpath_reg __iomem *vpath_reg,
	struct vxge_hw_device_hw_info *hw_info)
{
	u32 i, j;
	u64 val64;
	u64 data1 = 0ULL;
	u64 data2 = 0ULL;
	enum vxge_hw_status status = VXGE_HW_OK;
	u8 *serial_number = hw_info->serial_number;
	u8 *part_number = hw_info->part_number;
	u8 *product_desc = hw_info->product_desc;

	__vxge_hw_read_rts_ds(vpath_reg,
		VXGE_HW_RTS_ACCESS_STEER_DATA0_MEMO_ITEM_SERIAL_NUMBER);

	val64 = VXGE_HW_RTS_ACCESS_STEER_CTRL_ACTION(
			VXGE_HW_RTS_ACCESS_STEER_CTRL_ACTION_READ_MEMO_ENTRY) |
		VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL(
			VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL_FW_MEMO) |
		VXGE_HW_RTS_ACCESS_STEER_CTRL_STROBE |
		VXGE_HW_RTS_ACCESS_STEER_CTRL_OFFSET(0);

	status = __vxge_hw_pio_mem_write64(val64,
				&vpath_reg->rts_access_steer_ctrl,
				VXGE_HW_RTS_ACCESS_STEER_CTRL_STROBE,
				WAIT_FACTOR * VXGE_TIMER_DELAY);

	if (status != VXGE_HW_OK)
		return status;

	val64 = readq(&vpath_reg->rts_access_steer_ctrl);

	if (val64 & VXGE_HW_RTS_ACCESS_STEER_CTRL_RMACJ_STATUS) {
		data1 = readq(&vpath_reg->rts_access_steer_data0);
		((u64 *)serial_number)[0] = be64_to_cpu(data1);

		data2 = readq(&vpath_reg->rts_access_steer_data1);
		((u64 *)serial_number)[1] = be64_to_cpu(data2);
		status = VXGE_HW_OK;
	} else
		*serial_number = 0;

	__vxge_hw_read_rts_ds(vpath_reg,
			VXGE_HW_RTS_ACCESS_STEER_DATA0_MEMO_ITEM_PART_NUMBER);

	val64 = VXGE_HW_RTS_ACCESS_STEER_CTRL_ACTION(
			VXGE_HW_RTS_ACCESS_STEER_CTRL_ACTION_READ_MEMO_ENTRY) |
		VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL(
			VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL_FW_MEMO) |
		VXGE_HW_RTS_ACCESS_STEER_CTRL_STROBE |
		VXGE_HW_RTS_ACCESS_STEER_CTRL_OFFSET(0);

	status = __vxge_hw_pio_mem_write64(val64,
				&vpath_reg->rts_access_steer_ctrl,
				VXGE_HW_RTS_ACCESS_STEER_CTRL_STROBE,
				WAIT_FACTOR * VXGE_TIMER_DELAY);

	if (status != VXGE_HW_OK)
		return status;

	val64 = readq(&vpath_reg->rts_access_steer_ctrl);

	if (val64 & VXGE_HW_RTS_ACCESS_STEER_CTRL_RMACJ_STATUS) {

		data1 = readq(&vpath_reg->rts_access_steer_data0);
		((u64 *)part_number)[0] = be64_to_cpu(data1);

		data2 = readq(&vpath_reg->rts_access_steer_data1);
		((u64 *)part_number)[1] = be64_to_cpu(data2);

		status = VXGE_HW_OK;

	} else
		*part_number = 0;

	j = 0;

	for (i = VXGE_HW_RTS_ACCESS_STEER_DATA0_MEMO_ITEM_DESC_0;
	     i <= VXGE_HW_RTS_ACCESS_STEER_DATA0_MEMO_ITEM_DESC_3; i++) {

		__vxge_hw_read_rts_ds(vpath_reg, i);

		val64 = VXGE_HW_RTS_ACCESS_STEER_CTRL_ACTION(
			VXGE_HW_RTS_ACCESS_STEER_CTRL_ACTION_READ_MEMO_ENTRY) |
			VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL(
			VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL_FW_MEMO) |
			VXGE_HW_RTS_ACCESS_STEER_CTRL_STROBE |
			VXGE_HW_RTS_ACCESS_STEER_CTRL_OFFSET(0);

		status = __vxge_hw_pio_mem_write64(val64,
				&vpath_reg->rts_access_steer_ctrl,
				VXGE_HW_RTS_ACCESS_STEER_CTRL_STROBE,
				WAIT_FACTOR * VXGE_TIMER_DELAY);

		if (status != VXGE_HW_OK)
			return status;

		val64 = readq(&vpath_reg->rts_access_steer_ctrl);

		if (val64 & VXGE_HW_RTS_ACCESS_STEER_CTRL_RMACJ_STATUS) {

			data1 = readq(&vpath_reg->rts_access_steer_data0);
			((u64 *)product_desc)[j++] = be64_to_cpu(data1);

			data2 = readq(&vpath_reg->rts_access_steer_data1);
			((u64 *)product_desc)[j++] = be64_to_cpu(data2);

			status = VXGE_HW_OK;
		} else
			*product_desc = 0;
	}

	return status;
}

enum vxge_hw_status
vxge_hw_vpath_eprom_img_ver_get(
	u32 vp_id,
	struct vxge_hw_vpath_reg __iomem *vp_reg,
	struct vxge_hw_device_hw_info *hw_info)
{
	struct eprom_image *eprom_image_data;
	int i;
	u64 data0, val64;
	enum vxge_hw_status status = VXGE_HW_OK;

	for (i = 0; i < VXGE_HW_MAX_ROM_IMAGES; i++) {
		eprom_image_data = &hw_info->eprom_image_data[i];

		data0 = VXGE_HW_RTS_ACCESS_STEER_ROM_IMAGE_INDEX(i);
		writeq(data0, &vp_reg->rts_access_steer_data0);

		val64 = VXGE_HW_RTS_ACCESS_STEER_CTRL_ACTION(
			VXGE_HW_FW_API_GET_EPROM_REV) |
			VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL(
			VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL_FW_MEMO) |
			VXGE_HW_RTS_ACCESS_STEER_CTRL_STROBE |
			VXGE_HW_RTS_ACCESS_STEER_CTRL_OFFSET(0);

		status = __vxge_hw_pio_mem_write64(val64,
				&vp_reg->rts_access_steer_ctrl,
				VXGE_HW_RTS_ACCESS_STEER_CTRL_STROBE,
				WAIT_FACTOR * VXGE_TIMER_DELAY);

		if (status != VXGE_HW_OK)
			goto exit;
		val64 = readq(&vp_reg->rts_access_steer_ctrl);
		if (val64 & VXGE_HW_RTS_ACCESS_STEER_CTRL_RMACJ_STATUS) {

                        data0 = readq(&vp_reg->rts_access_steer_data0);
                        eprom_image_data->is_valid =
                                        VXGE_HW_GET_EPROM_IMAGE_VALID(data0);

                        if (eprom_image_data->is_valid) {
                                eprom_image_data->index =
                                        VXGE_HW_GET_EPROM_IMAGE_INDEX(data0);
                                eprom_image_data->type =
                                        VXGE_HW_GET_EPROM_IMAGE_TYPE(data0);
                                eprom_image_data->version =
                                        VXGE_HW_GET_EPROM_IMAGE_REV(data0);
                        } else
                                break;
                } else
			status = VXGE_HW_FAIL;
        }
exit:
	return status;
}
/*
 * __vxge_hw_vpath_fw_ver_get - Get the fw version
 * Returns FW Version
 */
enum vxge_hw_status
__vxge_hw_vpath_fw_ver_get(
	u32 vp_id,
	struct vxge_hw_vpath_reg __iomem *vpath_reg,
	struct vxge_hw_device_hw_info *hw_info)
{
	u64 val64;
	u64 data1 = 0ULL;
	u64 data2 = 0ULL;
	struct vxge_hw_device_version *fw_version = &hw_info->fw_version;
	struct vxge_hw_device_date *fw_date = &hw_info->fw_date;
	struct vxge_hw_device_version *flash_version = &hw_info->flash_version;
	struct vxge_hw_device_date *flash_date = &hw_info->flash_date;
	enum vxge_hw_status status = VXGE_HW_OK;

	val64 = VXGE_HW_RTS_ACCESS_STEER_CTRL_ACTION(
		VXGE_HW_RTS_ACCESS_STEER_CTRL_ACTION_READ_ENTRY) |
		VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL(
		VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL_FW_MEMO) |
		VXGE_HW_RTS_ACCESS_STEER_CTRL_STROBE |
		VXGE_HW_RTS_ACCESS_STEER_CTRL_OFFSET(0);

	status = __vxge_hw_pio_mem_write64(val64,
				&vpath_reg->rts_access_steer_ctrl,
				VXGE_HW_RTS_ACCESS_STEER_CTRL_STROBE,
				WAIT_FACTOR * VXGE_TIMER_DELAY);

	if (status != VXGE_HW_OK)
		goto exit;

	val64 = readq(&vpath_reg->rts_access_steer_ctrl);

	if (val64 & VXGE_HW_RTS_ACCESS_STEER_CTRL_RMACJ_STATUS) {

		data1 = readq(&vpath_reg->rts_access_steer_data0);
		data2 = readq(&vpath_reg->rts_access_steer_data1);

		fw_date->day =
			(u32)VXGE_HW_RTS_ACCESS_STEER_DATA0_GET_FW_VER_DAY(
						data1);
		fw_date->month =
			(u32)VXGE_HW_RTS_ACCESS_STEER_DATA0_GET_FW_VER_MONTH(
						data1);
		fw_date->year =
			(u32)VXGE_HW_RTS_ACCESS_STEER_DATA0_GET_FW_VER_YEAR(
						data1);

		snprintf(fw_date->date, VXGE_HW_FW_STRLEN, "%2.2d/%2.2d/%4.4d",
			fw_date->month, fw_date->day, fw_date->year);

		fw_version->major =
		    (u32)VXGE_HW_RTS_ACCESS_STEER_DATA0_GET_FW_VER_MAJOR(data1);
		fw_version->minor =
		    (u32)VXGE_HW_RTS_ACCESS_STEER_DATA0_GET_FW_VER_MINOR(data1);
		fw_version->build =
		    (u32)VXGE_HW_RTS_ACCESS_STEER_DATA0_GET_FW_VER_BUILD(data1);

		snprintf(fw_version->version, VXGE_HW_FW_STRLEN, "%d.%d.%d",
		    fw_version->major, fw_version->minor, fw_version->build);

		flash_date->day =
		  (u32)VXGE_HW_RTS_ACCESS_STEER_DATA1_GET_FLASH_VER_DAY(data2);
		flash_date->month =
		 (u32)VXGE_HW_RTS_ACCESS_STEER_DATA1_GET_FLASH_VER_MONTH(data2);
		flash_date->year =
		 (u32)VXGE_HW_RTS_ACCESS_STEER_DATA1_GET_FLASH_VER_YEAR(data2);

		snprintf(flash_date->date, VXGE_HW_FW_STRLEN,
			"%2.2d/%2.2d/%4.4d",
			flash_date->month, flash_date->day, flash_date->year);

		flash_version->major =
		 (u32)VXGE_HW_RTS_ACCESS_STEER_DATA1_GET_FLASH_VER_MAJOR(data2);
		flash_version->minor =
		 (u32)VXGE_HW_RTS_ACCESS_STEER_DATA1_GET_FLASH_VER_MINOR(data2);
		flash_version->build =
		 (u32)VXGE_HW_RTS_ACCESS_STEER_DATA1_GET_FLASH_VER_BUILD(data2);

		snprintf(flash_version->version, VXGE_HW_FW_STRLEN, "%d.%d.%d",
			flash_version->major, flash_version->minor,
			flash_version->build);

		status = VXGE_HW_OK;

	} else
		status = VXGE_HW_FAIL;
exit:
	return status;
}

/**
 * vxge_hw_device_flick_link_led - Flick (blink) link LED.
 * @hldev: HW device.
 * @on_off: TRUE if flickering to be on, FALSE to be off
 *
 * Flicker the link LED.
 */
enum vxge_hw_status
vxge_hw_device_flick_link_led(struct __vxge_hw_device *hldev,
			       u64 on_off)
{
	enum vxge_hw_status status = VXGE_HW_OK;
	u64 data0 = on_off, data1 = 0, steer_ctrl = 0;
	u32 fw_memo = VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL_FW_MEMO;

	if (hldev == NULL) {
		return VXGE_HW_ERR_INVALID_DEVICE;
	}

	status = vxge_hw_vpath_fw_api(hldev, hldev->first_vp_id,
			VXGE_HW_RTS_ACCESS_STEER_CTRL_ACTION_LED_CONTROL, 0,
			fw_memo, &data0, &data1, &steer_ctrl);

	return status;
}

/*
 * __vxge_hw_vpath_addr_get - Get the hw address entry for this vpath
 *               from MAC address table.
 */
enum vxge_hw_status
__vxge_hw_vpath_addr_get(
	u32 vp_id, struct vxge_hw_vpath_reg __iomem *vpath_reg,
	u8 (macaddr)[ETH_ALEN], u8 (macaddr_mask)[ETH_ALEN])
{
	u32 i;
	u64 val64;
	u64 data1 = 0ULL;
	u64 data2 = 0ULL;
	u64 action = VXGE_HW_RTS_ACCESS_STEER_CTRL_ACTION_LIST_FIRST_ENTRY;
	enum vxge_hw_status status = VXGE_HW_OK;

	while (1) {
		val64 = VXGE_HW_RTS_ACCESS_STEER_CTRL_ACTION(action) |
			VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL(
			VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL_DA) |
			VXGE_HW_RTS_ACCESS_STEER_CTRL_STROBE |
			VXGE_HW_RTS_ACCESS_STEER_CTRL_OFFSET(0);

		status = __vxge_hw_pio_mem_write64(val64,
					&vpath_reg->rts_access_steer_ctrl,
					VXGE_HW_RTS_ACCESS_STEER_CTRL_STROBE,
					WAIT_FACTOR * VXGE_TIMER_DELAY);

		if (status != VXGE_HW_OK)
			break;

		val64 = readq(&vpath_reg->rts_access_steer_ctrl);

		if (val64 & VXGE_HW_RTS_ACCESS_STEER_CTRL_RMACJ_STATUS) {

			data1 = readq(&vpath_reg->rts_access_steer_data0);
			data2 = readq(&vpath_reg->rts_access_steer_data1);

			data1 =
			 VXGE_HW_RTS_ACCESS_STEER_DATA0_GET_DA_MAC_ADDR(data1);
			data2 =
			 VXGE_HW_RTS_ACCESS_STEER_DATA1_GET_DA_MAC_ADDR_MASK(
								data2);

			for (i = ETH_ALEN; i > 0; i--) {
				macaddr[i-1] = (u8)(data1 & 0xFF);
				data1 >>= 8;

				macaddr_mask[i-1] = (u8)(data2 & 0xFF);
				data2 >>= 8;
			}

			if (is_valid_ether_addr(macaddr)) {
				status = VXGE_HW_OK;
				break;
			}

			action =
			  VXGE_HW_RTS_ACCESS_STEER_CTRL_ACTION_LIST_NEXT_ENTRY;
		} else
			status = VXGE_HW_FAIL;
	}

	return status;
}

/*
 * vxge_hw_vpath_rts_rth_set - Set/configure RTS hashing.
 */
enum vxge_hw_status vxge_hw_vpath_rts_rth_set(
			struct __vxge_hw_vpath_handle *vp,
			enum vxge_hw_rth_algoritms algorithm,
			struct vxge_hw_rth_hash_types *hash_type,
			u16 bucket_size)
{
	u64 data0 = 0ULL, data1 = 0ULL, steer_ctrl = 0ULL;
	enum vxge_hw_status status = VXGE_HW_OK;

	if (vp == NULL) {
		status = VXGE_HW_ERR_INVALID_HANDLE;
		goto exit;
	}

	status = vxge_hw_vpath_fw_api(vp->vpath->hldev, vp->vpath->vp_id,
		VXGE_HW_RTS_ACCESS_STEER_CTRL_ACTION_READ_ENTRY, 0,
		VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL_RTH_GEN_CFG,
		&data0, &data1, &steer_ctrl);
	if (status != VXGE_HW_OK)
		goto exit;

	data0 &= ~(VXGE_HW_RTS_ACCESS_STEER_DATA0_RTH_GEN_BUCKET_SIZE(0xf) |
			VXGE_HW_RTS_ACCESS_STEER_DATA0_RTH_GEN_ALG_SEL(0x3));

	data0 |= VXGE_HW_RTS_ACCESS_STEER_DATA0_RTH_GEN_RTH_EN |
	VXGE_HW_RTS_ACCESS_STEER_DATA0_RTH_GEN_BUCKET_SIZE(bucket_size) |
	VXGE_HW_RTS_ACCESS_STEER_DATA0_RTH_GEN_ALG_SEL(algorithm);

	if (hash_type->hash_type_tcpipv4_en)
		data0 |= VXGE_HW_RTS_ACCESS_STEER_DATA0_RTH_GEN_RTH_TCP_IPV4_EN;

	if (hash_type->hash_type_ipv4_en)
		data0 |= VXGE_HW_RTS_ACCESS_STEER_DATA0_RTH_GEN_RTH_IPV4_EN;

	if (hash_type->hash_type_tcpipv6_en)
		data0 |= VXGE_HW_RTS_ACCESS_STEER_DATA0_RTH_GEN_RTH_TCP_IPV6_EN;

	if (hash_type->hash_type_ipv6_en)
		data0 |= VXGE_HW_RTS_ACCESS_STEER_DATA0_RTH_GEN_RTH_IPV6_EN;

	if (hash_type->hash_type_tcpipv6ex_en)
		data0 |=
		VXGE_HW_RTS_ACCESS_STEER_DATA0_RTH_GEN_RTH_TCP_IPV6_EX_EN;

	if (hash_type->hash_type_ipv6ex_en)
		data0 |= VXGE_HW_RTS_ACCESS_STEER_DATA0_RTH_GEN_RTH_IPV6_EX_EN;

	if (VXGE_HW_RTS_ACCESS_STEER_DATA0_GET_RTH_GEN_ACTIVE_TABLE(data0))
		data0 &= ~VXGE_HW_RTS_ACCESS_STEER_DATA0_RTH_GEN_ACTIVE_TABLE;
	else
		data0 |= VXGE_HW_RTS_ACCESS_STEER_DATA0_RTH_GEN_ACTIVE_TABLE;

	data1 = 0;
	status = vxge_hw_vpath_fw_api(vp->vpath->hldev, vp->vpath->vp_id,
		VXGE_HW_RTS_ACCESS_STEER_CTRL_ACTION_WRITE_ENTRY, 0,
		VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL_RTH_GEN_CFG,
		&data0, &data1, &steer_ctrl);
exit:
	return status;
}

static void
vxge_hw_rts_rth_data0_data1_get(u32 j, u64 *data0, u64 *data1,
				u16 flag, u8 *itable)
{
	switch (flag) {
	case 1:
		*data0 = VXGE_HW_RTS_ACCESS_STEER_DATA0_RTH_ITEM0_BUCKET_NUM(j)|
			VXGE_HW_RTS_ACCESS_STEER_DATA0_RTH_ITEM0_ENTRY_EN |
			VXGE_HW_RTS_ACCESS_STEER_DATA0_RTH_ITEM0_BUCKET_DATA(
			itable[j]);
	case 2:
		*data0 |=
			VXGE_HW_RTS_ACCESS_STEER_DATA0_RTH_ITEM1_BUCKET_NUM(j)|
			VXGE_HW_RTS_ACCESS_STEER_DATA0_RTH_ITEM1_ENTRY_EN |
			VXGE_HW_RTS_ACCESS_STEER_DATA0_RTH_ITEM1_BUCKET_DATA(
			itable[j]);
	case 3:
		*data1 = VXGE_HW_RTS_ACCESS_STEER_DATA1_RTH_ITEM0_BUCKET_NUM(j)|
			VXGE_HW_RTS_ACCESS_STEER_DATA1_RTH_ITEM0_ENTRY_EN |
			VXGE_HW_RTS_ACCESS_STEER_DATA1_RTH_ITEM0_BUCKET_DATA(
			itable[j]);
	case 4:
		*data1 |=
			VXGE_HW_RTS_ACCESS_STEER_DATA1_RTH_ITEM1_BUCKET_NUM(j)|
			VXGE_HW_RTS_ACCESS_STEER_DATA1_RTH_ITEM1_ENTRY_EN |
			VXGE_HW_RTS_ACCESS_STEER_DATA1_RTH_ITEM1_BUCKET_DATA(
			itable[j]);
	default:
		return;
	}
}
/*
 * vxge_hw_vpath_rts_rth_itable_set - Set/configure indirection table (IT).
 */
enum vxge_hw_status vxge_hw_vpath_rts_rth_itable_set(
			struct __vxge_hw_vpath_handle **vpath_handles,
			u32 vpath_count,
			u8 *mtable,
			u8 *itable,
			u32 itable_size)
{
	u32 i, j, action, rts_table;
	u64 data0;
	u64 data1, steer_ctrl = 0;
	u32 max_entries;
	enum vxge_hw_status status = VXGE_HW_OK;
	struct __vxge_hw_vpath_handle *vp = vpath_handles[0];

	if (vp == NULL) {
		status = VXGE_HW_ERR_INVALID_HANDLE;
		goto exit;
	}

	max_entries = (((u32)1) << itable_size);

	action = VXGE_HW_RTS_ACCESS_STEER_CTRL_ACTION_WRITE_ENTRY;
	rts_table =
		VXGE_HW_RTS_ACS_STEER_CTRL_DATA_STRUCT_SEL_RTH_MULTI_IT;
	for (i = 0; i < vpath_count; i++) {

		for (j = 0; j < max_entries;) {

			data0 = 0;
			data1 = 0;

			while (j < max_entries) {
				if (mtable[itable[j]] != i) {
					j++;
					continue;
				}
				vxge_hw_rts_rth_data0_data1_get(j,
					&data0, &data1, 1, itable);
				j++;
				break;
			}

			while (j < max_entries) {
				if (mtable[itable[j]] != i) {
					j++;
					continue;
				}
				vxge_hw_rts_rth_data0_data1_get(j,
					&data0, &data1, 2, itable);
				j++;
				break;
			}

			while (j < max_entries) {
				if (mtable[itable[j]] != i) {
					j++;
					continue;
				}
				vxge_hw_rts_rth_data0_data1_get(j,
					&data0, &data1, 3, itable);
				j++;
				break;
			}

			while (j < max_entries) {
				if (mtable[itable[j]] != i) {
					j++;
					continue;
				}
				vxge_hw_rts_rth_data0_data1_get(j,
					&data0, &data1, 4, itable);
				j++;
				break;
			}

			if (data0 != 0) {
				vp = vpath_handles[i];
				status = vxge_hw_vpath_fw_api(vp->vpath->hldev,
							vp->vpath->vp_id,
							action, 0, rts_table,
							&data0, &data1,
							&steer_ctrl);
				if (status != VXGE_HW_OK)
					goto exit;
			}
		}
	}
exit:
	return status;
}

/**
 * vxge_hw_vpath_check_leak - Check for memory leak
 * @ringh: Handle to the ring object used for receive
 *
 * If PRC_RXD_DOORBELL_VPn.NEW_QW_CNT is larger or equal to
 * PRC_CFG6_VPn.RXD_SPAT then a leak has occurred.
 * Returns: VXGE_HW_FAIL, if leak has occurred.
 *
 */
enum vxge_hw_status
vxge_hw_vpath_check_leak(struct __vxge_hw_ring *ring)
{
	enum vxge_hw_status status = VXGE_HW_OK;
	u64 rxd_new_count, rxd_spat;

	if (ring == NULL)
		return status;

	rxd_new_count = readl(&ring->vp_reg->prc_rxd_doorbell);
	rxd_spat = readq(&ring->vp_reg->prc_cfg6);
	rxd_spat = VXGE_HW_PRC_CFG6_GET_RXD_SPAT(rxd_spat);

	if (rxd_new_count >= rxd_spat)
		status = VXGE_HW_FAIL;

	return status;
}

/*
 * __vxge_hw_vpath_mgmt_read
 * This routine reads the vpath_mgmt registers
 */
static enum vxge_hw_status
__vxge_hw_vpath_mgmt_read(
	struct __vxge_hw_device *hldev,
	struct __vxge_hw_virtualpath *vpath)
{
	u32 i, mtu = 0, max_pyld = 0;
	u64 val64;
	enum vxge_hw_status status = VXGE_HW_OK;

	for (i = 0; i < VXGE_HW_MAC_MAX_MAC_PORT_ID; i++) {

		val64 = readq(&vpath->vpmgmt_reg->
				rxmac_cfg0_port_vpmgmt_clone[i]);
		max_pyld =
			(u32)
			VXGE_HW_RXMAC_CFG0_PORT_VPMGMT_CLONE_GET_MAX_PYLD_LEN
			(val64);
		if (mtu < max_pyld)
			mtu = max_pyld;
	}

	vpath->max_mtu = mtu + VXGE_HW_MAC_HEADER_MAX_SIZE;

	val64 = readq(&vpath->vpmgmt_reg->xgmac_gen_status_vpmgmt_clone);

	if (val64 & VXGE_HW_XGMAC_GEN_STATUS_VPMGMT_CLONE_XMACJ_NTWK_OK)
		VXGE_HW_DEVICE_LINK_STATE_SET(vpath->hldev, VXGE_HW_LINK_UP);
	else
		VXGE_HW_DEVICE_LINK_STATE_SET(vpath->hldev, VXGE_HW_LINK_DOWN);

	return status;
}

/*
 * __vxge_hw_vpath_reset_check - Check if resetting the vpath completed
 * This routine checks the vpath_rst_in_prog register to see if
 * adapter completed the reset process for the vpath
 */
enum vxge_hw_status
__vxge_hw_vpath_reset_check(struct __vxge_hw_virtualpath *vpath)
{
	enum vxge_hw_status status;

	status = __vxge_hw_device_register_poll(
			&vpath->hldev->common_reg->vpath_rst_in_prog,
			VXGE_HW_VPATH_RST_IN_PROG_VPATH_RST_IN_PROG(
				1 << (16 - vpath->vp_id)),
			vpath->hldev->config.device_poll_millis);

	return status;
}

/*
 * __vxge_hw_vpath_reset
 * This routine resets the vpath on the device
 */
enum vxge_hw_status
__vxge_hw_vpath_reset(struct __vxge_hw_device *hldev, u32 vp_id)
{
	u64 val64;
	enum vxge_hw_status status = VXGE_HW_OK;

	val64 = VXGE_HW_CMN_RSTHDLR_CFG0_SW_RESET_VPATH(1 << (16 - vp_id));

	__vxge_hw_pio_mem_write32_upper((u32)vxge_bVALn(val64, 0, 32),
				&hldev->common_reg->cmn_rsthdlr_cfg0);

	return status;
}

/*
 * __vxge_hw_vpath_sw_reset
 * This routine resets the vpath structures
 */
enum vxge_hw_status
__vxge_hw_vpath_sw_reset(struct __vxge_hw_device *hldev, u32 vp_id)
{
	enum vxge_hw_status status = VXGE_HW_OK;
	struct __vxge_hw_virtualpath *vpath;

	vpath = (struct __vxge_hw_virtualpath *)&hldev->virtual_paths[vp_id];

	if (vpath->ringh) {
		status = __vxge_hw_ring_reset(vpath->ringh);
		if (status != VXGE_HW_OK)
			goto exit;
	}

	if (vpath->fifoh)
		status = __vxge_hw_fifo_reset(vpath->fifoh);
exit:
	return status;
}

/*
 * __vxge_hw_vpath_prc_configure
 * This routine configures the prc registers of virtual path using the config
 * passed
 */
void
__vxge_hw_vpath_prc_configure(struct __vxge_hw_device *hldev, u32 vp_id)
{
	u64 val64;
	struct __vxge_hw_virtualpath *vpath;
	struct vxge_hw_vp_config *vp_config;
	struct vxge_hw_vpath_reg __iomem *vp_reg;

	vpath = &hldev->virtual_paths[vp_id];
	vp_reg = vpath->vp_reg;
	vp_config = vpath->vp_config;

	if (vp_config->ring.enable == VXGE_HW_RING_DISABLE)
		return;

	val64 = readq(&vp_reg->prc_cfg1);
	val64 |= VXGE_HW_PRC_CFG1_RTI_TINT_DISABLE;
	val64 &= ~VXGE_HW_PRC_CFG1_RX_TIMER_VAL(0x1FFFFFFF);
        val64 |= VXGE_HW_PRC_CFG1_RX_TIMER_VAL(1);
	writeq(val64, &vp_reg->prc_cfg1);

	val64 = readq(&vpath->vp_reg->prc_cfg6);
	val64 |= VXGE_HW_PRC_CFG6_DOORBELL_MODE_EN;
	writeq(val64, &vpath->vp_reg->prc_cfg6);
	val64 = readq(&vp_reg->prc_cfg7);

	if (vpath->vp_config->ring.scatter_mode !=
		VXGE_HW_RING_SCATTER_MODE_USE_FLASH_DEFAULT) {

		val64 &= ~VXGE_HW_PRC_CFG7_SCATTER_MODE(0x3);

		switch (vpath->vp_config->ring.scatter_mode) {
		case VXGE_HW_RING_SCATTER_MODE_A:
			val64 |= VXGE_HW_PRC_CFG7_SCATTER_MODE(
					VXGE_HW_PRC_CFG7_SCATTER_MODE_A);
			break;
		case VXGE_HW_RING_SCATTER_MODE_B:
			val64 |= VXGE_HW_PRC_CFG7_SCATTER_MODE(
					VXGE_HW_PRC_CFG7_SCATTER_MODE_B);
			break;
		case VXGE_HW_RING_SCATTER_MODE_C:
			val64 |= VXGE_HW_PRC_CFG7_SCATTER_MODE(
					VXGE_HW_PRC_CFG7_SCATTER_MODE_C);
			break;
		}
	}

	writeq(val64, &vp_reg->prc_cfg7);

	writeq(VXGE_HW_PRC_CFG5_RXD0_ADD(
				__vxge_hw_ring_first_block_address_get(
					vpath->ringh) >> 3), &vp_reg->prc_cfg5);

	val64 = readq(&vp_reg->prc_cfg4);
	val64 |= VXGE_HW_PRC_CFG4_IN_SVC;
	val64 &= ~VXGE_HW_PRC_CFG4_RING_MODE(0x3);

	val64 |= VXGE_HW_PRC_CFG4_RING_MODE(
			VXGE_HW_PRC_CFG4_RING_MODE_ONE_BUFFER);

	if (hldev->config.rth_en == VXGE_HW_RTH_DISABLE)
		val64 |= VXGE_HW_PRC_CFG4_RTH_DISABLE;
	else
		val64 &= ~VXGE_HW_PRC_CFG4_RTH_DISABLE;

	writeq(val64, &vp_reg->prc_cfg4);
	return;
}

/*
 * __vxge_hw_vpath_kdfc_configure
 * This routine configures the kdfc registers of virtual path using the
 * config passed
 */
enum vxge_hw_status
__vxge_hw_vpath_kdfc_configure(struct __vxge_hw_device *hldev, u32 vp_id)
{
	u64 val64;
	u64 vpath_stride;
	enum vxge_hw_status status = VXGE_HW_OK;
	struct __vxge_hw_virtualpath *vpath;
	struct vxge_hw_vpath_reg __iomem *vp_reg;

	vpath = &hldev->virtual_paths[vp_id];
	vp_reg = vpath->vp_reg;
	status = __vxge_hw_kdfc_swapper_set(hldev->legacy_reg, vp_reg);

	if (status != VXGE_HW_OK)
		goto exit;

	val64 = readq(&vp_reg->kdfc_drbl_triplet_total);

	vpath->max_kdfc_db =
		(u32)VXGE_HW_KDFC_DRBL_TRIPLET_TOTAL_GET_KDFC_MAX_SIZE(
			val64+1)/2;

	if (vpath->vp_config->fifo.enable == VXGE_HW_FIFO_ENABLE) {

		vpath->max_nofl_db = vpath->max_kdfc_db;

		if (vpath->max_nofl_db <
			((vpath->vp_config->fifo.memblock_size /
			(vpath->vp_config->fifo.max_frags *
			sizeof(struct vxge_hw_fifo_txd))) *
			vpath->vp_config->fifo.fifo_blocks)) {

			return VXGE_HW_BADCFG_FIFO_BLOCKS;
		}
		val64 = VXGE_HW_KDFC_FIFO_TRPL_PARTITION_LENGTH_0(
				(vpath->max_nofl_db*2)-1);
	}

	writeq(val64, &vp_reg->kdfc_fifo_trpl_partition);

	writeq(VXGE_HW_KDFC_FIFO_TRPL_CTRL_TRIPLET_ENABLE,
		&vp_reg->kdfc_fifo_trpl_ctrl);

	val64 = readq(&vp_reg->kdfc_trpl_fifo_0_ctrl);

	val64 &= ~(VXGE_HW_KDFC_TRPL_FIFO_0_CTRL_MODE(0x3) |
		   VXGE_HW_KDFC_TRPL_FIFO_0_CTRL_SELECT(0xFF));

	val64 |= VXGE_HW_KDFC_TRPL_FIFO_0_CTRL_MODE(
		 VXGE_HW_KDFC_TRPL_FIFO_0_CTRL_MODE_NON_OFFLOAD_ONLY) |
#ifndef __BIG_ENDIAN
		 VXGE_HW_KDFC_TRPL_FIFO_0_CTRL_SWAP_EN |
#endif
		 VXGE_HW_KDFC_TRPL_FIFO_0_CTRL_SELECT(0);

	writeq(val64, &vp_reg->kdfc_trpl_fifo_0_ctrl);
	writeq((u64)0, &vp_reg->kdfc_trpl_fifo_0_wb_address);
	wmb();
	vpath_stride = readq(&hldev->toc_reg->toc_kdfc_vpath_stride);

	vpath->nofl_db =
		(struct __vxge_hw_non_offload_db_wrapper __iomem *)
		(hldev->kdfc + (vp_id *
		VXGE_HW_TOC_KDFC_VPATH_STRIDE_GET_TOC_KDFC_VPATH_STRIDE(
					vpath_stride)));
exit:
	return status;
}

/*
 * __vxge_hw_vpath_mac_configure
 * This routine configures the mac of virtual path using the config passed
 */
enum vxge_hw_status
__vxge_hw_vpath_mac_configure(struct __vxge_hw_device *hldev, u32 vp_id)
{
	u64 val64;
	enum vxge_hw_status status = VXGE_HW_OK;
	struct __vxge_hw_virtualpath *vpath;
	struct vxge_hw_vp_config *vp_config;
	struct vxge_hw_vpath_reg __iomem *vp_reg;

	vpath = &hldev->virtual_paths[vp_id];
	vp_reg = vpath->vp_reg;
	vp_config = vpath->vp_config;

	writeq(VXGE_HW_XMAC_VSPORT_CHOICE_VSPORT_NUMBER(
			vpath->vsport_number), &vp_reg->xmac_vsport_choice);

	if (vp_config->ring.enable == VXGE_HW_RING_ENABLE) {

		val64 = readq(&vp_reg->xmac_rpa_vcfg);

		if (vp_config->rpa_strip_vlan_tag !=
			VXGE_HW_VPATH_RPA_STRIP_VLAN_TAG_USE_FLASH_DEFAULT) {
			if (vp_config->rpa_strip_vlan_tag)
				val64 |= VXGE_HW_XMAC_RPA_VCFG_STRIP_VLAN_TAG;
			else
				val64 &= ~VXGE_HW_XMAC_RPA_VCFG_STRIP_VLAN_TAG;
		}

		writeq(val64, &vp_reg->xmac_rpa_vcfg);
		val64 = readq(&vp_reg->rxmac_vcfg0);

		if (vp_config->mtu !=
				VXGE_HW_VPATH_USE_FLASH_DEFAULT_INITIAL_MTU) {
			val64 &= ~VXGE_HW_RXMAC_VCFG0_RTS_MAX_FRM_LEN(0x3fff);
			if ((vp_config->mtu  +
				VXGE_HW_MAC_HEADER_MAX_SIZE) < vpath->max_mtu)
				val64 |= VXGE_HW_RXMAC_VCFG0_RTS_MAX_FRM_LEN(
					vp_config->mtu  +
					VXGE_HW_MAC_HEADER_MAX_SIZE);
			else
				val64 |= VXGE_HW_RXMAC_VCFG0_RTS_MAX_FRM_LEN(
					vpath->max_mtu);
		}

		writeq(val64, &vp_reg->rxmac_vcfg0);

		val64 = readq(&vp_reg->rxmac_vcfg1);

		val64 &= ~(VXGE_HW_RXMAC_VCFG1_RTS_RTH_MULTI_IT_BD_MODE(0x3) |
			VXGE_HW_RXMAC_VCFG1_RTS_RTH_MULTI_IT_EN_MODE);

		if (hldev->config.rth_it_type ==
				VXGE_HW_RTH_IT_TYPE_MULTI_IT) {
			val64 |= VXGE_HW_RXMAC_VCFG1_RTS_RTH_MULTI_IT_BD_MODE(
				0x2) |
				VXGE_HW_RXMAC_VCFG1_RTS_RTH_MULTI_IT_EN_MODE;
		}

		writeq(val64, &vp_reg->rxmac_vcfg1);
	}
	return status;
}

/*
 * vxge_hw_vpath_tim_configure
 * This routine configures the tim registers of virtual path using the config
 * passed
 */
enum vxge_hw_status
vxge_hw_vpath_tim_configure(struct __vxge_hw_device *hldev, u32 vp_id)
{
	u64 val64;
	enum vxge_hw_status status = VXGE_HW_OK;
	struct __vxge_hw_virtualpath *vpath;
	struct vxge_hw_vpath_reg __iomem *vp_reg;
	struct vxge_hw_vp_config *config;

	vpath = &hldev->virtual_paths[vp_id];
	vp_reg = vpath->vp_reg;
	config = vpath->vp_config;

	writeq((u64)0, &vp_reg->tim_dest_addr);
	writeq((u64)0, &vp_reg->tim_vpath_map);
	writeq((u64)0, &vp_reg->tim_bitmap);
	writeq((u64)0, &vp_reg->tim_remap);

	if (config->ring.enable == VXGE_HW_RING_ENABLE)
		writeq(VXGE_HW_TIM_RING_ASSN_INT_NUM(
			(vp_id * VXGE_HW_MAX_INTR_PER_VP) +
			VXGE_HW_VPATH_INTR_RX), &vp_reg->tim_ring_assn);

	val64 = readq(&vp_reg->tim_pci_cfg);
	val64 |= VXGE_HW_TIM_PCI_CFG_ADD_PAD;
	writeq(val64, &vp_reg->tim_pci_cfg);

	if (config->fifo.enable == VXGE_HW_FIFO_ENABLE) {

		val64 = readq(&vp_reg->tim_cfg1_int_num[VXGE_HW_VPATH_INTR_TX]);

		if (config->tti.btimer_val != VXGE_HW_USE_FLASH_DEFAULT) {
			val64 &= ~VXGE_HW_TIM_CFG1_INT_NUM_BTIMER_VAL(
				0x3ffffff);
			val64 |= VXGE_HW_TIM_CFG1_INT_NUM_BTIMER_VAL(
					config->tti.btimer_val);
		}

		val64 &= ~VXGE_HW_TIM_CFG1_INT_NUM_BITMP_EN;

		if (config->tti.timer_ac_en != VXGE_HW_USE_FLASH_DEFAULT) {
			if (config->tti.timer_ac_en)
				val64 |= VXGE_HW_TIM_CFG1_INT_NUM_TIMER_AC;
			else
				val64 &= ~VXGE_HW_TIM_CFG1_INT_NUM_TIMER_AC;
		}

		if (config->tti.timer_ci_en != VXGE_HW_USE_FLASH_DEFAULT) {
			if (config->tti.timer_ci_en)
				val64 |= VXGE_HW_TIM_CFG1_INT_NUM_TIMER_CI;
			else
				val64 &= ~VXGE_HW_TIM_CFG1_INT_NUM_TIMER_CI;
		}

		if (config->tti.urange_a != VXGE_HW_USE_FLASH_DEFAULT) {
			val64 &= ~VXGE_HW_TIM_CFG1_INT_NUM_URNG_A(0x3f);
			val64 |= VXGE_HW_TIM_CFG1_INT_NUM_URNG_A(
					config->tti.urange_a);
		}

		if (config->tti.urange_b != VXGE_HW_USE_FLASH_DEFAULT) {
			val64 &= ~VXGE_HW_TIM_CFG1_INT_NUM_URNG_B(0x3f);
			val64 |= VXGE_HW_TIM_CFG1_INT_NUM_URNG_B(
					config->tti.urange_b);
		}

		if (config->tti.urange_c != VXGE_HW_USE_FLASH_DEFAULT) {
			val64 &= ~VXGE_HW_TIM_CFG1_INT_NUM_URNG_C(0x3f);
			val64 |= VXGE_HW_TIM_CFG1_INT_NUM_URNG_C(
					config->tti.urange_c);
		}

		writeq(val64, &vp_reg->tim_cfg1_int_num[VXGE_HW_VPATH_INTR_TX]);
		vpath->tim_tti_cfg1_saved = val64;

		val64 = readq(&vp_reg->tim_cfg2_int_num[VXGE_HW_VPATH_INTR_TX]);

		if (config->tti.uec_a != VXGE_HW_USE_FLASH_DEFAULT) {
			val64 &= ~VXGE_HW_TIM_CFG2_INT_NUM_UEC_A(0xffff);
			val64 |= VXGE_HW_TIM_CFG2_INT_NUM_UEC_A(
						config->tti.uec_a);
		}

		if (config->tti.uec_b != VXGE_HW_USE_FLASH_DEFAULT) {
			val64 &= ~VXGE_HW_TIM_CFG2_INT_NUM_UEC_B(0xffff);
			val64 |= VXGE_HW_TIM_CFG2_INT_NUM_UEC_B(
						config->tti.uec_b);
		}

		if (config->tti.uec_c != VXGE_HW_USE_FLASH_DEFAULT) {
			val64 &= ~VXGE_HW_TIM_CFG2_INT_NUM_UEC_C(0xffff);
			val64 |= VXGE_HW_TIM_CFG2_INT_NUM_UEC_C(
						config->tti.uec_c);
		}

		if (config->tti.uec_d != VXGE_HW_USE_FLASH_DEFAULT) {
			val64 &= ~VXGE_HW_TIM_CFG2_INT_NUM_UEC_D(0xffff);
			val64 |= VXGE_HW_TIM_CFG2_INT_NUM_UEC_D(
						config->tti.uec_d);
		}

		writeq(val64, &vp_reg->tim_cfg2_int_num[VXGE_HW_VPATH_INTR_TX]);
		val64 = readq(&vp_reg->tim_cfg3_int_num[VXGE_HW_VPATH_INTR_TX]);

		if (config->tti.timer_ri_en != VXGE_HW_USE_FLASH_DEFAULT) {
			if (config->tti.timer_ri_en)
				val64 |= VXGE_HW_TIM_CFG3_INT_NUM_TIMER_RI;
			else
				val64 &= ~VXGE_HW_TIM_CFG3_INT_NUM_TIMER_RI;
		}

		if (config->tti.rtimer_val != VXGE_HW_USE_FLASH_DEFAULT) {
			val64 &= ~VXGE_HW_TIM_CFG3_INT_NUM_RTIMER_VAL(
					0x3ffffff);
			val64 |= VXGE_HW_TIM_CFG3_INT_NUM_RTIMER_VAL(
					config->tti.rtimer_val);
		}

		if (config->tti.util_sel != VXGE_HW_USE_FLASH_DEFAULT) {
			val64 &= ~VXGE_HW_TIM_CFG3_INT_NUM_UTIL_SEL(0x3f);
			val64 |= VXGE_HW_TIM_CFG3_INT_NUM_UTIL_SEL(vp_id);
		}

		if (config->tti.ltimer_val != VXGE_HW_USE_FLASH_DEFAULT) {
			val64 &= ~VXGE_HW_TIM_CFG3_INT_NUM_LTIMER_VAL(
					0x3ffffff);
			val64 |= VXGE_HW_TIM_CFG3_INT_NUM_LTIMER_VAL(
					config->tti.ltimer_val);
		}

		writeq(val64, &vp_reg->tim_cfg3_int_num[VXGE_HW_VPATH_INTR_TX]);
		vpath->tim_tti_cfg3_saved = val64;
	}

	if (config->ring.enable == VXGE_HW_RING_ENABLE) {

		val64 = readq(&vp_reg->tim_cfg1_int_num[VXGE_HW_VPATH_INTR_RX]);

		if (config->rti.btimer_val != VXGE_HW_USE_FLASH_DEFAULT) {
			val64 &= ~VXGE_HW_TIM_CFG1_INT_NUM_BTIMER_VAL(
					0x3ffffff);
			val64 |= VXGE_HW_TIM_CFG1_INT_NUM_BTIMER_VAL(
					config->rti.btimer_val);
		}

		val64 &= ~VXGE_HW_TIM_CFG1_INT_NUM_BITMP_EN;

		if (config->rti.timer_ac_en != VXGE_HW_USE_FLASH_DEFAULT) {
			if (config->rti.timer_ac_en)
				val64 |= VXGE_HW_TIM_CFG1_INT_NUM_TIMER_AC;
			else
				val64 &= ~VXGE_HW_TIM_CFG1_INT_NUM_TIMER_AC;
		}

		if (config->rti.timer_ci_en != VXGE_HW_USE_FLASH_DEFAULT) {
			if (config->rti.timer_ci_en)
				val64 |= VXGE_HW_TIM_CFG1_INT_NUM_TIMER_CI;
			else
				val64 &= ~VXGE_HW_TIM_CFG1_INT_NUM_TIMER_CI;
		}

		if (config->rti.urange_a != VXGE_HW_USE_FLASH_DEFAULT) {
			val64 &= ~VXGE_HW_TIM_CFG1_INT_NUM_URNG_A(0x3f);
			val64 |= VXGE_HW_TIM_CFG1_INT_NUM_URNG_A(
					config->rti.urange_a);
		}

		if (config->rti.urange_b != VXGE_HW_USE_FLASH_DEFAULT) {
			val64 &= ~VXGE_HW_TIM_CFG1_INT_NUM_URNG_B(0x3f);
			val64 |= VXGE_HW_TIM_CFG1_INT_NUM_URNG_B(
					config->rti.urange_b);
		}

		if (config->rti.urange_c != VXGE_HW_USE_FLASH_DEFAULT) {
			val64 &= ~VXGE_HW_TIM_CFG1_INT_NUM_URNG_C(0x3f);
			val64 |= VXGE_HW_TIM_CFG1_INT_NUM_URNG_C(
					config->rti.urange_c);
		}

		writeq(val64, &vp_reg->tim_cfg1_int_num[VXGE_HW_VPATH_INTR_RX]);
		vpath->tim_rti_cfg1_saved = val64;

		val64 = readq(&vp_reg->tim_cfg2_int_num[VXGE_HW_VPATH_INTR_RX]);

		if (config->rti.uec_a != VXGE_HW_USE_FLASH_DEFAULT) {
			val64 &= ~VXGE_HW_TIM_CFG2_INT_NUM_UEC_A(0xffff);
			val64 |= VXGE_HW_TIM_CFG2_INT_NUM_UEC_A(
						config->rti.uec_a);
		}

		if (config->rti.uec_b != VXGE_HW_USE_FLASH_DEFAULT) {
			val64 &= ~VXGE_HW_TIM_CFG2_INT_NUM_UEC_B(0xffff);
			val64 |= VXGE_HW_TIM_CFG2_INT_NUM_UEC_B(
						config->rti.uec_b);
		}

		if (config->rti.uec_c != VXGE_HW_USE_FLASH_DEFAULT) {
			val64 &= ~VXGE_HW_TIM_CFG2_INT_NUM_UEC_C(0xffff);
			val64 |= VXGE_HW_TIM_CFG2_INT_NUM_UEC_C(
						config->rti.uec_c);
		}

		if (config->rti.uec_d != VXGE_HW_USE_FLASH_DEFAULT) {
			val64 &= ~VXGE_HW_TIM_CFG2_INT_NUM_UEC_D(0xffff);
			val64 |= VXGE_HW_TIM_CFG2_INT_NUM_UEC_D(
						config->rti.uec_d);
		}

		writeq(val64, &vp_reg->tim_cfg2_int_num[VXGE_HW_VPATH_INTR_RX]);
		val64 = readq(&vp_reg->tim_cfg3_int_num[VXGE_HW_VPATH_INTR_RX]);

		if (config->rti.timer_ri_en != VXGE_HW_USE_FLASH_DEFAULT) {
			if (config->rti.timer_ri_en)
				val64 |= VXGE_HW_TIM_CFG3_INT_NUM_TIMER_RI;
			else
				val64 &= ~VXGE_HW_TIM_CFG3_INT_NUM_TIMER_RI;
		}

		if (config->rti.rtimer_val != VXGE_HW_USE_FLASH_DEFAULT) {
			val64 &= ~VXGE_HW_TIM_CFG3_INT_NUM_RTIMER_VAL(
					0x3ffffff);
			val64 |= VXGE_HW_TIM_CFG3_INT_NUM_RTIMER_VAL(
					config->rti.rtimer_val);
		}

		if (config->rti.util_sel != VXGE_HW_USE_FLASH_DEFAULT) {
			val64 &= ~VXGE_HW_TIM_CFG3_INT_NUM_UTIL_SEL(0x3f);
			val64 |= VXGE_HW_TIM_CFG3_INT_NUM_UTIL_SEL(vp_id);
		}

		if (config->rti.ltimer_val != VXGE_HW_USE_FLASH_DEFAULT) {
			val64 &= ~VXGE_HW_TIM_CFG3_INT_NUM_LTIMER_VAL(
					0x3ffffff);
			val64 |= VXGE_HW_TIM_CFG3_INT_NUM_LTIMER_VAL(
					config->rti.ltimer_val);
		}

		writeq(val64, &vp_reg->tim_cfg3_int_num[VXGE_HW_VPATH_INTR_RX]);
		vpath->tim_rti_cfg3_saved = val64;
	}

	val64 = 0;

	writeq(val64, &vp_reg->tim_cfg1_int_num[VXGE_HW_VPATH_INTR_EINTA]);

	writeq(val64, &vp_reg->tim_cfg2_int_num[VXGE_HW_VPATH_INTR_EINTA]);
	writeq(val64, &vp_reg->tim_cfg3_int_num[VXGE_HW_VPATH_INTR_EINTA]);
	writeq(val64, &vp_reg->tim_cfg1_int_num[VXGE_HW_VPATH_INTR_BMAP]);
	writeq(val64, &vp_reg->tim_cfg2_int_num[VXGE_HW_VPATH_INTR_BMAP]);
	writeq(val64, &vp_reg->tim_cfg3_int_num[VXGE_HW_VPATH_INTR_BMAP]);

	val64 = VXGE_HW_TIM_WRKLD_CLC_WRKLD_EVAL_PRD(150);
	val64 |= VXGE_HW_TIM_WRKLD_CLC_WRKLD_EVAL_DIV(0);
	val64 |= VXGE_HW_TIM_WRKLD_CLC_CNT_RX_TX(3);

	writeq(val64, &vp_reg->tim_wrkld_clc);

	return status;
}

void
vxge_hw_vpath_tti_ci_set(struct __vxge_hw_fifo *fifo)
{
	struct vxge_hw_vpath_reg __iomem *vp_reg;
	struct vxge_hw_vp_config *config;

	u64 val64;
	vp_reg = fifo->vp_reg;
	config = fifo->vp_config;

	if (config->fifo.enable == VXGE_HW_FIFO_ENABLE) {
		val64 = readq(&vp_reg->tim_cfg1_int_num[VXGE_HW_VPATH_INTR_TX]);

		if (config->tti.timer_ci_en != VXGE_HW_TIM_TIMER_CI_ENABLE) {
			config->tti.timer_ci_en = VXGE_HW_TIM_TIMER_CI_ENABLE;
			val64 |= VXGE_HW_TIM_CFG1_INT_NUM_TIMER_CI;
			fifo->tim_tti_cfg1_saved = val64;
			writeq(val64,
			    &vp_reg->tim_cfg1_int_num[VXGE_HW_VPATH_INTR_TX]);
		}
	}
	return;
}
void
vxge_hw_vpath_tti_ci_reset(struct __vxge_hw_fifo *fifo)
{
        struct vxge_hw_vpath_reg __iomem *vp_reg;
        struct vxge_hw_vp_config *config;
        u64 val64;

        vp_reg = fifo->vp_reg;
        config = fifo->vp_config;

        if (config->fifo.enable == VXGE_HW_FIFO_ENABLE) {
                val64 = readq(&vp_reg->tim_cfg1_int_num[VXGE_HW_VPATH_INTR_TX]);

                if (config->tti.timer_ci_en != VXGE_HW_TIM_TIMER_CI_DISABLE) {
                        config->tti.timer_ci_en = VXGE_HW_TIM_TIMER_CI_DISABLE;
                        val64 &= ~VXGE_HW_TIM_CFG1_INT_NUM_TIMER_CI;
			fifo->tim_tti_cfg1_saved = val64;
                        writeq(val64,
                            &vp_reg->tim_cfg1_int_num[VXGE_HW_VPATH_INTR_TX]);
                }
        }
        return;
}

/*
 * __vxge_hw_vpath_initialize
 * This routine is the final phase of init which initializes the
 * registers of the vpath using the configuration passed.
 */
enum vxge_hw_status
__vxge_hw_vpath_initialize(struct __vxge_hw_device *hldev, u32 vp_id)
{
	u64 val64;
	u32 val32;
	int i;
	enum vxge_hw_status status = VXGE_HW_OK;
	struct __vxge_hw_virtualpath *vpath;
	struct vxge_hw_vpath_reg __iomem *vp_reg;

	vpath = &hldev->virtual_paths[vp_id];

	if (!(hldev->vpath_assignments & vxge_mBIT(vp_id))) {
		status = VXGE_HW_ERR_VPATH_NOT_AVAILABLE;
		goto exit;
	}
	vp_reg = vpath->vp_reg;
	status = __vxge_hw_legacy_swapper_set(hldev->legacy_reg);
	if (status != VXGE_HW_OK)
		goto exit;

	status =  __vxge_hw_vpath_swapper_set(vpath->vp_reg);

	if (status != VXGE_HW_OK)
		goto exit;
	val64 = readq(&vpath->vpmgmt_reg->xmac_vsport_choices_vp);

	for (i = 0; i < VXGE_HW_MAX_VIRTUAL_PATHS; i++) {
		if (val64 & vxge_mBIT(i))
			vpath->vsport_number = i;
	}

	status =  __vxge_hw_vpath_mac_configure(hldev, vp_id);

	if (status != VXGE_HW_OK)
		goto exit;

	status =  __vxge_hw_vpath_kdfc_configure(hldev, vp_id);

	if (status != VXGE_HW_OK)
		goto exit;

	status = vxge_hw_vpath_tim_configure(hldev, vp_id);

	if (status != VXGE_HW_OK)
		goto exit;

	val64 = readq(&vp_reg->rtdma_rd_optimization_ctrl);

	/* Get MRRS value from device control */
	status  = __vxge_hw_vpath_pci_read(vpath, 1, 0x78, &val32);

	if (status == VXGE_HW_OK) {
		val32 = (val32 & VXGE_HW_PCI_EXP_DEVCTL_READRQ) >> 12;
		val64 &=
		    ~(VXGE_HW_RTDMA_RD_OPTIMIZATION_CTRL_FB_FILL_THRESH(7));
		val64 |=
		    VXGE_HW_RTDMA_RD_OPTIMIZATION_CTRL_FB_FILL_THRESH(val32);

		val64 |= VXGE_HW_RTDMA_RD_OPTIMIZATION_CTRL_FB_WAIT_FOR_SPACE;
	}

	val64 &= ~(VXGE_HW_RTDMA_RD_OPTIMIZATION_CTRL_FB_ADDR_BDRY(7));
	val64 |=
	    VXGE_HW_RTDMA_RD_OPTIMIZATION_CTRL_FB_ADDR_BDRY(
		    VXGE_HW_MAX_PAYLOAD_SIZE_512);

	val64 |= VXGE_HW_RTDMA_RD_OPTIMIZATION_CTRL_FB_ADDR_BDRY_EN;
	writeq(val64, &vp_reg->rtdma_rd_optimization_ctrl);

exit:
	return status;
}

/*
 * __vxge_hw_vp_initialize - Initialize Virtual Path structure
 * This routine is the initial phase of init which resets the vpath and
 * initializes the software support structures.
 */
enum vxge_hw_status
__vxge_hw_vp_initialize(struct __vxge_hw_device *hldev, u32 vp_id,
			struct vxge_hw_vp_config *config)
{
	struct __vxge_hw_virtualpath *vpath;
	enum vxge_hw_status status = VXGE_HW_OK;

	if (!(hldev->vpath_assignments & vxge_mBIT(vp_id))) {
		status = VXGE_HW_ERR_VPATH_NOT_AVAILABLE;
		goto exit;
	}

	vpath = &hldev->virtual_paths[vp_id];

	vpath->vp_id = vp_id;
	vpath->vp_open = VXGE_HW_VP_OPEN;
	vpath->hldev = hldev;
	vpath->vp_config = config;
	vpath->vp_reg = hldev->vpath_reg[vp_id];
	vpath->vpmgmt_reg = hldev->vpmgmt_reg[vp_id];

	__vxge_hw_vpath_reset(hldev, vp_id);

	status = __vxge_hw_vpath_reset_check(vpath);

	if (status != VXGE_HW_OK) {
		memset(vpath, 0, sizeof(struct __vxge_hw_virtualpath));
		goto exit;
	}

	INIT_LIST_HEAD(&vpath->vpath_handles);

	vpath->sw_stats = &hldev->stats.sw_dev_info_stats.vpath_info[vp_id];

	VXGE_HW_DEVICE_TIM_INT_MASK_SET(hldev->tim_int_mask0,
		hldev->tim_int_mask1, vp_id);

	status = __vxge_hw_vpath_initialize(hldev, vp_id);

	if (status != VXGE_HW_OK) {
		__vxge_hw_vp_terminate(hldev, vp_id);
		goto exit;
	}

	status = __vxge_hw_vpath_mgmt_read(hldev, vpath);
exit:
	return status;
}

/*
 * __vxge_hw_vp_terminate - Terminate Virtual Path structure
 * This routine closes all channels it opened and freeup memory
 */
void
__vxge_hw_vp_terminate(struct __vxge_hw_device *hldev, u32 vp_id)
{
	struct __vxge_hw_virtualpath *vpath;

	vpath = &hldev->virtual_paths[vp_id];

	if (vpath->vp_open == VXGE_HW_VP_NOT_OPEN)
		goto exit;

	VXGE_HW_DEVICE_TIM_INT_MASK_RESET(vpath->hldev->tim_int_mask0,
		vpath->hldev->tim_int_mask1, vpath->vp_id);
	hldev->stats.hw_dev_info_stats.vpath_info[vpath->vp_id] = NULL;

	memset(vpath, 0, sizeof(struct __vxge_hw_virtualpath));
exit:
	return;
}

/**
 * vxge_hw_vpath_tx_bw_set - Set the bandwidth for a vpath.
 * @hldev: HW device handle.
 * @vp_id: Vpath Id.
 * __vxge_hw_channel_type type: Bandwidth for Tx or Rx channel
 * @bandwidth: Assigned Bandwidth in Mbps
 *
 * Set the bandwidth for a given vpath
 *
 */
enum vxge_hw_status vxge_hw_vpath_tx_bw_set(
	struct __vxge_hw_device *hldev,
	u32 vp_id, u32 bandwidth)
{
	enum vxge_hw_status status = VXGE_HW_OK;

	if (vp_id > VXGE_HW_MAX_VPATH_ID_TX_BW_SUPPORT) {
		status = VXGE_HW_ERR_VPATH_NOT_AVAILABLE;
		goto exit;
	}

	if (bandwidth == VXGE_HW_VPATH_TX_BW_LIMIT_DEFAULT)
		goto exit;

	if ((bandwidth < VXGE_HW_VPATH_TX_BW_LIMIT_MIN) ||
		(bandwidth > VXGE_HW_VPATH_TX_BW_LIMIT_MAX)) {
		status = VXGE_HW_ERR_INVALID_MIN_BANDWIDTH;
		goto exit;
	}

	hldev->config.vp_config[vp_id].tx_bw_limit = bandwidth;

	vxge_hw_tx_bw_set(hldev, vp_id);

exit:
	return status;
}

/**
 * vxge_hw_vpath_rx_bw_set - Set the bandwidth for a vpath.
 * @hldev: HW device handle.
 * @vp_id: Vpath Id.
 * __vxge_hw_channel_type type: Bandwidth for Tx or Rx channel
 * @bandwidth: Assigned Bandwidth in Mbps
 *
 * Set the bandwidth for a given vpath
 *
 */
enum vxge_hw_status vxge_hw_vpath_rx_bw_set(
	struct __vxge_hw_device *hldev,
	u32 vp_id,
	u32 bandwidth,
	u32 priority)
{
	u32 prev_bandwidth;
	u32 prev_priority;

	enum vxge_hw_status status = VXGE_HW_OK;

	if (vp_id >= VXGE_HW_MAX_VIRTUAL_PATHS) {
		status = VXGE_HW_ERR_VPATH_NOT_AVAILABLE;
		goto exit;
	}

	if ((bandwidth < VXGE_HW_VPATH_RX_BW_LIMIT_MIN) ||
		(bandwidth > VXGE_HW_VPATH_RX_BW_LIMIT_MAX)) {
		if (bandwidth != VXGE_HW_VPATH_RX_BW_LIMIT_DEFAULT) {
			status = VXGE_HW_BADCFG_VPATH_BANDWIDTH_LIMIT;
			goto exit;
		}
	}

	if ((priority < VXGE_HW_VPATH_PRIORITY_HIGH) ||
		(priority > VXGE_HW_VPATH_PRIORITY_LOW)) {
		if (priority != VXGE_HW_VPATH_PRIORITY_DEFAULT) {
			status = VXGE_HW_BADCFG_VPATH_PRIORITY;
			goto exit;
		}
	}

	prev_bandwidth = hldev->config.vp_config[vp_id].rx_bw_limit;
	prev_priority = hldev->config.vp_config[vp_id].vp_prio;

	hldev->config.vp_config[vp_id].vp_prio = priority;
	hldev->config.vp_config[vp_id].rx_bw_limit = bandwidth;

	status = vxge_hw_rx_bw_set(hldev, vp_id);
	if (status != VXGE_HW_OK) {
		hldev->config.vp_config[vp_id].rx_bw_limit = prev_bandwidth;
		hldev->config.vp_config[vp_id].vp_prio = prev_priority;
	}

exit:
	return status;
}

/*
 * vxge_hw_vpath_mtu_set - Set MTU.
 * Set new MTU value. Example, to use jumbo frames:
 * vxge_hw_vpath_mtu_set(my_device, 9600);
 */
void
vxge_hw_vpath_mtu_set(struct __vxge_hw_vpath_handle *vp, u32 new_mtu)
{
	u64 val64;
	enum vxge_hw_status status = VXGE_HW_OK;
	struct __vxge_hw_virtualpath *vpath;

	vpath = vp->vpath;

	new_mtu += VXGE_HW_MAC_HEADER_MAX_SIZE;

	if ((new_mtu < VXGE_HW_MIN_MTU) || (new_mtu > vpath->max_mtu))
		status = VXGE_HW_ERR_INVALID_MTU_SIZE;

	val64 = readq(&vpath->vp_reg->rxmac_vcfg0);

	val64 &= ~VXGE_HW_RXMAC_VCFG0_RTS_MAX_FRM_LEN(0x3fff);
	val64 |= VXGE_HW_RXMAC_VCFG0_RTS_MAX_FRM_LEN(new_mtu);

	writeq(val64, &vpath->vp_reg->rxmac_vcfg0);

	/* Flush the write operation */
	val64 = readq(&vpath->vp_reg->rxmac_vcfg0);

	vpath->vp_config->mtu = new_mtu - VXGE_HW_MAC_HEADER_MAX_SIZE;

	return;
}

/*
 * vxge_hw_vpath_open - Open a virtual path on a given adapter
 * This function is used to open access to virtual path of an
 * adapter for offload, GRO operations. This function returns
 * synchronously.
 */
enum vxge_hw_status
vxge_hw_vpath_open(struct __vxge_hw_device *hldev,
		   struct vxge_hw_vpath_attr *attr,
		   struct __vxge_hw_vpath_handle **vpath_handle)
{
	struct __vxge_hw_virtualpath *vpath;
	struct __vxge_hw_vpath_handle *vp;
	enum vxge_hw_status status;

	vpath = &hldev->virtual_paths[attr->vp_id];

	if (vpath->vp_open == VXGE_HW_VP_OPEN) {
		status = VXGE_HW_ERR_INVALID_STATE;
		goto vpath_open_exit1;
	}

	status = __vxge_hw_vp_initialize(hldev, attr->vp_id,
			&hldev->config.vp_config[attr->vp_id]);

	if (status != VXGE_HW_OK)
		goto vpath_open_exit1;

	vp = (struct __vxge_hw_vpath_handle *)
		vmalloc(sizeof(struct __vxge_hw_vpath_handle));
	if (vp == NULL) {
		status = VXGE_HW_ERR_OUT_OF_MEMORY;
		goto vpath_open_exit2;
	}

	memset(vp, 0, sizeof(struct __vxge_hw_vpath_handle));

	vp->vpath = vpath;

	if (vpath->vp_config->fifo.enable == VXGE_HW_FIFO_ENABLE) {
		status = __vxge_hw_fifo_create(vp, &attr->fifo_attr);
		if (status != VXGE_HW_OK)
			goto vpath_open_exit6;
	}

	if (vpath->vp_config->ring.enable == VXGE_HW_RING_ENABLE) {
		status = __vxge_hw_ring_create(vp, &attr->ring_attr);
		if (status != VXGE_HW_OK)
			goto vpath_open_exit7;

		__vxge_hw_vpath_prc_configure(hldev, attr->vp_id);
	}

	vpath->fifoh->bandwidth =
		hldev->config.vp_config[attr->vp_id].tx_bw_limit;

	vpath->fifoh->tx_intr_num =
		(attr->vp_id * VXGE_HW_MAX_INTR_PER_VP)  +
			VXGE_HW_VPATH_INTR_TX;

	vpath->stats_block = __vxge_hw_blockpool_block_allocate(hldev,
				VXGE_HW_BLOCK_SIZE);

	if (vpath->stats_block == NULL) {
		status = VXGE_HW_ERR_OUT_OF_MEMORY;
		goto vpath_open_exit8;
	}

	vpath->hw_stats = (struct vxge_hw_vpath_stats_hw_info *)vpath->
			stats_block->memblock;
	memset(vpath->hw_stats, 0,
		sizeof(struct vxge_hw_vpath_stats_hw_info));

	hldev->stats.hw_dev_info_stats.vpath_info[attr->vp_id] =
						vpath->hw_stats;

	vpath->hw_stats_sav =
		&hldev->stats.hw_dev_info_stats.vpath_info_sav[attr->vp_id];
	memset(vpath->hw_stats_sav, 0,
			sizeof(struct vxge_hw_vpath_stats_hw_info));

	writeq(vpath->stats_block->dma_addr, &vpath->vp_reg->stats_cfg);

	status = vxge_hw_vpath_stats_enable(vp);
	if (status != VXGE_HW_OK)
		goto vpath_open_exit8;

	list_add(&vp->item, &vpath->vpath_handles);

	hldev->vpaths_deployed |= vxge_mBIT(vpath->vp_id);

	*vpath_handle = vp;

	attr->fifo_attr.userdata = vpath->fifoh;
	attr->ring_attr.userdata = vpath->ringh;

	return VXGE_HW_OK;

vpath_open_exit8:
	if (vpath->ringh != NULL)
		__vxge_hw_ring_delete(vp);
vpath_open_exit7:
	if (vpath->fifoh != NULL)
		__vxge_hw_fifo_delete(vp);
vpath_open_exit6:

	vfree(vp);
vpath_open_exit2:
	__vxge_hw_vp_terminate(hldev, attr->vp_id);
vpath_open_exit1:

	return status;
}

/*
 * vxge_hw_vpath_rx_doorbell_init -  Post the count of the refreshed region
 * of RxD list
 * @vp: vpath handle
 *
 * This function decides on the Rxd replenish count depending on the
 * descriptor memory that has been allocated to this VPath.
 */
void
vxge_hw_vpath_rx_doorbell_init(struct __vxge_hw_vpath_handle *vp)
{
	struct __vxge_hw_virtualpath *vpath = NULL;
	u64 new_count;
	struct __vxge_hw_ring *ring;

	vpath = vp->vpath;
	ring = vpath->ringh;

	if (vpath->hldev->titan1) {
		new_count = readq(&vpath->vp_reg->rxdmem_size);
		new_count &= 0x1fff;
	} else
		new_count = ring->config->ring_blocks * VXGE_HW_BLOCK_SIZE / 8;

	writeq(VXGE_HW_PRC_RXD_DOORBELL_NEW_QW_CNT(new_count),
		&vpath->vp_reg->prc_rxd_doorbell);
	readl(&vpath->vp_reg->prc_rxd_doorbell);
}

/*
 * vxge_hw_vpath_close - Close the handle got from previous vpath (vpath) open
 * This function is used to close access to virtual path opened
 * earlier.
 */
enum vxge_hw_status vxge_hw_vpath_close(struct __vxge_hw_vpath_handle *vp)
{
	struct __vxge_hw_virtualpath *vpath = NULL;
	struct __vxge_hw_device *devh = NULL;
	u32 vp_id = vp->vpath->vp_id;
	u32 is_empty = TRUE;
	enum vxge_hw_status status = VXGE_HW_OK;

	vpath = vp->vpath;
	devh = vpath->hldev;

	if (vpath->vp_open == VXGE_HW_VP_NOT_OPEN) {
		status = VXGE_HW_ERR_VPATH_NOT_OPEN;
		goto vpath_close_exit;
	}

	list_del(&vp->item);

	if (!list_empty(&vpath->vpath_handles)) {
		list_add(&vp->item, &vpath->vpath_handles);
		is_empty = FALSE;
	}

	if (!is_empty) {
		status = VXGE_HW_FAIL;
		goto vpath_close_exit;
	}

	devh->vpaths_deployed &= ~vxge_mBIT(vp_id);

	if (vpath->ringh != NULL)
		__vxge_hw_ring_delete(vp);

	if (vpath->fifoh != NULL)
		__vxge_hw_fifo_delete(vp);

	if (vpath->stats_block != NULL)
		__vxge_hw_blockpool_block_free(devh, vpath->stats_block);

	vfree(vp);

	__vxge_hw_vp_terminate(devh, vp_id);

	vpath->vp_open = VXGE_HW_VP_NOT_OPEN;

vpath_close_exit:
	return status;
}

/*
 * vxge_hw_vpath_reset - Resets vpath
 * This function is used to request a reset of vpath
 */
enum vxge_hw_status vxge_hw_vpath_reset(struct __vxge_hw_vpath_handle *vp)
{
	enum vxge_hw_status status;
	u32 vp_id;
	struct __vxge_hw_virtualpath *vpath = vp->vpath;

	vp_id = vpath->vp_id;

	if (vpath->vp_open == VXGE_HW_VP_NOT_OPEN) {
		status = VXGE_HW_ERR_VPATH_NOT_OPEN;
		goto exit;
	}

	status = __vxge_hw_vpath_reset(vpath->hldev, vp_id);
	if (status == VXGE_HW_OK)
		vpath->sw_stats->soft_reset_cnt++;
exit:
	return status;
}

/*
 * vxge_hw_vpath_recover_from_reset - Poll for reset complete and re-initialize.
 * This function poll's for the vpath reset completion and re initializes
 * the vpath.
 */
enum vxge_hw_status
vxge_hw_vpath_recover_from_reset(struct __vxge_hw_vpath_handle *vp)
{
	struct __vxge_hw_virtualpath *vpath = NULL;
	enum vxge_hw_status status;
	struct __vxge_hw_device *hldev;
	u32 vp_id;

	vp_id = vp->vpath->vp_id;
	vpath = vp->vpath;
	hldev = vpath->hldev;

	if (vpath->vp_open == VXGE_HW_VP_NOT_OPEN) {
		status = VXGE_HW_ERR_VPATH_NOT_OPEN;
		goto exit;
	}

	status = __vxge_hw_vpath_reset_check(vpath);
	if (status != VXGE_HW_OK)
		goto exit;

	status = __vxge_hw_vpath_sw_reset(hldev, vp_id);
	if (status != VXGE_HW_OK)
		goto exit;

	status = __vxge_hw_vpath_initialize(hldev, vp_id);
	if (status != VXGE_HW_OK)
		goto exit;

	if (vpath->ringh != NULL)
		__vxge_hw_vpath_prc_configure(hldev, vp_id);

	memset(vpath->hw_stats, 0,
		sizeof(struct vxge_hw_vpath_stats_hw_info));

	memset(vpath->hw_stats_sav, 0,
		sizeof(struct vxge_hw_vpath_stats_hw_info));

	writeq(vpath->stats_block->dma_addr,
		&vpath->vp_reg->stats_cfg);

	status = vxge_hw_vpath_stats_enable(vp);

exit:
	return status;
}

/*
 * vxge_hw_vpath_enable - Enable vpath.
 * This routine clears the vpath reset thereby enabling a vpath
 * to start forwarding frames and generating interrupts.
 */
void
vxge_hw_vpath_enable(struct __vxge_hw_vpath_handle *vp)
{
	struct __vxge_hw_device *hldev;
	u64 val64;

	hldev = vp->vpath->hldev;

	val64 = VXGE_HW_CMN_RSTHDLR_CFG1_CLR_VPATH_RESET(
		1 << (16 - vp->vpath->vp_id));

	__vxge_hw_pio_mem_write32_upper((u32)vxge_bVALn(val64, 0, 32),
		&hldev->common_reg->cmn_rsthdlr_cfg1);
}

/*
 * vxge_hw_vpath_stats_enable - Enable vpath h/wstatistics.
 * Enable the DMA vpath statistics. The function is to be called to re-enable
 * the adapter to update stats into the host memory
 */
enum vxge_hw_status
vxge_hw_vpath_stats_enable(struct __vxge_hw_vpath_handle *vp)
{
	u64 val64;
	enum vxge_hw_status status = VXGE_HW_OK;
	struct __vxge_hw_virtualpath *vpath;

	vpath = vp->vpath;

	if (vpath->vp_open == VXGE_HW_VP_NOT_OPEN) {
		status = VXGE_HW_ERR_VPATH_NOT_OPEN;
		goto exit;
	}

	memcpy(vpath->hw_stats_sav, vpath->hw_stats,
			sizeof(struct vxge_hw_vpath_stats_hw_info));
	if (vpath->hldev->config.stats_read_method ==
						VXGE_HW_STATS_READ_METHOD_DMA) {
		val64 = readq(&vpath->hldev->common_reg->stats_cfg0);
		val64 |= VXGE_HW_STATS_CFG0_STATS_ENABLE(
						(1 << (16 - vpath->vp_id)));

		__vxge_hw_pio_mem_write32_upper((u32)vxge_bVALn(val64, 0, 32),
					&vpath->hldev->common_reg->stats_cfg0);
	} else
		status = __vxge_hw_vpath_stats_get(vpath, vpath->hw_stats);

exit:
	return status;
}

/*
 * __vxge_hw_vpath_stats_access - Get the statistics from the given location
 *                           and offset and perform an operation
 */
enum vxge_hw_status
__vxge_hw_vpath_stats_access(struct __vxge_hw_virtualpath *vpath,
			     u32 operation, u32 offset, u64 *stat)
{
	u64 val64;
	enum vxge_hw_status status = VXGE_HW_OK;
	struct vxge_hw_vpath_reg __iomem *vp_reg;

	if (vpath->vp_open == VXGE_HW_VP_NOT_OPEN) {
		status = VXGE_HW_ERR_VPATH_NOT_OPEN;
		goto vpath_stats_access_exit;
	}

	vp_reg = vpath->vp_reg;

	val64 =  VXGE_HW_XMAC_STATS_ACCESS_CMD_OP(operation) |
		 VXGE_HW_XMAC_STATS_ACCESS_CMD_STROBE |
		 VXGE_HW_XMAC_STATS_ACCESS_CMD_OFFSET_SEL(offset);

	status = __vxge_hw_pio_mem_write64(val64,
				&vp_reg->xmac_stats_access_cmd,
				VXGE_HW_XMAC_STATS_ACCESS_CMD_STROBE,
				vpath->hldev->config.device_poll_millis);

	if ((status == VXGE_HW_OK) && (operation == VXGE_HW_STATS_OP_READ))
		*stat = readq(&vp_reg->xmac_stats_access_data);
	else
		*stat = 0;

vpath_stats_access_exit:
	return status;
}

/*
 * __vxge_hw_vpath_xmac_tx_stats_get - Get the TX Statistics of a vpath
 */
enum vxge_hw_status
__vxge_hw_vpath_xmac_tx_stats_get(
	struct __vxge_hw_virtualpath *vpath,
	struct vxge_hw_xmac_vpath_tx_stats *vpath_tx_stats)
{
	u64 *val64;
	int i;
	u32 offset = VXGE_HW_STATS_VPATH_TX_OFFSET;
	enum vxge_hw_status status = VXGE_HW_OK;

	val64 = (u64 *) vpath_tx_stats;

	if (vpath->vp_open == VXGE_HW_VP_NOT_OPEN) {
		status = VXGE_HW_ERR_VPATH_NOT_OPEN;
		goto exit;
	}

	for (i = 0; i < sizeof(struct vxge_hw_xmac_vpath_tx_stats) / 8; i++) {
		status = __vxge_hw_vpath_stats_access(vpath,
					VXGE_HW_STATS_OP_READ,
					offset, val64);
		if (status != VXGE_HW_OK)
			goto exit;
		offset++;
		val64++;
	}
exit:
	return status;
}

/*
 * __vxge_hw_vpath_xmac_rx_stats_get - Get the RX Statistics of a vpath
 */
enum vxge_hw_status
__vxge_hw_vpath_xmac_rx_stats_get(struct __vxge_hw_virtualpath *vpath,
			struct vxge_hw_xmac_vpath_rx_stats *vpath_rx_stats)
{
	u64 *val64;
	enum vxge_hw_status status = VXGE_HW_OK;
	int i;
	u32 offset = VXGE_HW_STATS_VPATH_RX_OFFSET;
	val64 = (u64 *) vpath_rx_stats;

	if (vpath->vp_open == VXGE_HW_VP_NOT_OPEN) {
		status = VXGE_HW_ERR_VPATH_NOT_OPEN;
		goto exit;
	}
	for (i = 0; i < sizeof(struct vxge_hw_xmac_vpath_rx_stats) / 8; i++) {
		status = __vxge_hw_vpath_stats_access(vpath,
					VXGE_HW_STATS_OP_READ,
					offset >> 3, val64);
		if (status != VXGE_HW_OK)
			goto exit;

		offset += 8;
		val64++;
	}
exit:
	return status;
}

/*
 * __vxge_hw_vpath_stats_get - Get the vpath hw statistics.
 */
enum vxge_hw_status __vxge_hw_vpath_stats_get(
			struct __vxge_hw_virtualpath *vpath,
			struct vxge_hw_vpath_stats_hw_info *hw_stats)
{
	enum vxge_hw_status status = VXGE_HW_OK;

	if (vpath->vp_open == VXGE_HW_VP_NOT_OPEN) {
		status = VXGE_HW_ERR_VPATH_NOT_OPEN;
		goto exit;
	}

	status = __vxge_hw_vpath_xmac_tx_stats_get(vpath, &hw_stats->tx_stats);
	if (status != VXGE_HW_OK)
		goto exit;

	status = __vxge_hw_vpath_xmac_rx_stats_get(vpath, &hw_stats->rx_stats);
	if (status != VXGE_HW_OK)
		goto exit;
exit:
	return status;
}

/*
 * __vxge_hw_blockpool_create - Create block pool
 */

enum vxge_hw_status
__vxge_hw_blockpool_create(struct __vxge_hw_device *hldev,
			   struct __vxge_hw_blockpool *blockpool,
			   u32 pool_size)
{
	u32 i;
	struct __vxge_hw_blockpool_entry *entry = NULL;
	void *memblock;
	dma_addr_t dma_addr;

	struct pci_dev *dma_handle;
	struct pci_dev *acc_handle;

	enum vxge_hw_status status = VXGE_HW_OK;

	if (blockpool == NULL) {
		status = VXGE_HW_FAIL;
		goto blockpool_create_exit;
	}

	blockpool->hldev = hldev;
	blockpool->block_size = VXGE_HW_BLOCK_SIZE;

	INIT_LIST_HEAD(&blockpool->free_block_list);
	INIT_LIST_HEAD(&blockpool->free_entry_list);

	for (i = 0; i < pool_size; i++) {
		entry = kzalloc(sizeof(struct __vxge_hw_blockpool_entry),
				GFP_KERNEL);
		if (entry == NULL) {
			__vxge_hw_blockpool_destroy(blockpool);
			status = VXGE_HW_ERR_OUT_OF_MEMORY;
			goto blockpool_create_exit;
		}
		list_add(&entry->item, &blockpool->free_entry_list);
	}

	for (i = 0; i < pool_size; i++) {

		memblock = vxge_os_dma_malloc(
				hldev->pdev,
				VXGE_HW_BLOCK_SIZE,
				&dma_handle,
				&acc_handle);

		if (memblock == NULL) {
			__vxge_hw_blockpool_destroy(blockpool);
			status = VXGE_HW_ERR_OUT_OF_MEMORY;
			goto blockpool_create_exit;
		}

		dma_addr = vxge_dma_map(hldev->pdev, memblock,
				VXGE_HW_BLOCK_SIZE, PCI_DMA_BIDIRECTIONAL);

		if (unlikely(vxge_do_pci_dma_mapping_error(hldev->pdev,
				dma_addr))) {

			vxge_os_dma_free(hldev->pdev, memblock, &acc_handle);
			__vxge_hw_blockpool_destroy(blockpool);
			status = VXGE_HW_ERR_OUT_OF_MEMORY;
			goto blockpool_create_exit;
		}

		if (!list_empty(&blockpool->free_entry_list))
			entry = (struct __vxge_hw_blockpool_entry *)
				list_entry((&blockpool->free_entry_list)->next,
					struct __vxge_hw_blockpool_entry,
					item);

		if (entry == NULL)
			entry =
			    kzalloc(sizeof(struct __vxge_hw_blockpool_entry),
					GFP_KERNEL);
		if (entry != NULL) {
			list_del(&entry->item);
			entry->length = VXGE_HW_BLOCK_SIZE;
			entry->memblock = memblock;
			entry->dma_addr = dma_addr;

			entry->acc_handle = acc_handle;
			entry->dma_handle = dma_handle;

			list_add(&entry->item,
					  &blockpool->free_block_list);
		} else {
			__vxge_hw_blockpool_destroy(blockpool);
			status = VXGE_HW_ERR_OUT_OF_MEMORY;
			goto blockpool_create_exit;
		}
	}

blockpool_create_exit:
	return status;
}

/*
 * __vxge_hw_blockpool_destroy - Deallocates the block pool
 */

void __vxge_hw_blockpool_destroy(struct __vxge_hw_blockpool *blockpool)
{

	struct __vxge_hw_device *hldev;
	struct list_head *p, *n;

	if (blockpool == NULL)
		goto exit;

	hldev = blockpool->hldev;

	list_for_each_safe(p, n, &blockpool->free_block_list) {

		vxge_dma_unmap(hldev->pdev,
			((struct __vxge_hw_blockpool_entry *)p)->dma_addr,
			((struct __vxge_hw_blockpool_entry *)p)->length,
			PCI_DMA_BIDIRECTIONAL);

		vxge_os_dma_free(hldev->pdev,
			((struct __vxge_hw_blockpool_entry *)p)->memblock,
			&((struct __vxge_hw_blockpool_entry *) p)->acc_handle);

		list_del(
			&((struct __vxge_hw_blockpool_entry *)p)->item);
		kfree(p);
	}

	list_for_each_safe(p, n, &blockpool->free_entry_list) {
		list_del(
			&((struct __vxge_hw_blockpool_entry *)p)->item);
		kfree((void *)p);
	}
exit:
	return;
}

/*
 * __vxge_hw_blockpool_malloc - Allocate a memory block from pool
 * Allocates a block of memory of given size, either from block pool
 * or by calling vxge_os_dma_malloc()
 */
void *
__vxge_hw_blockpool_malloc(struct __vxge_hw_device *devh,
		struct vxge_hw_mempool_dma *dma_object)
{
	struct __vxge_hw_blockpool_entry *entry = NULL;
	struct __vxge_hw_blockpool  *blockpool;
	void *memblock = NULL;

	blockpool = &devh->block_pool;

	if (!list_empty(&blockpool->free_block_list))
		entry = (struct __vxge_hw_blockpool_entry *)
			list_entry((&blockpool->free_block_list)->next,
				struct __vxge_hw_blockpool_entry,
				item);
	if (entry != NULL) {
		list_del(&entry->item);
		dma_object->addr = entry->dma_addr;
		dma_object->handle = entry->dma_handle;
		dma_object->acc_handle = entry->acc_handle;
		memblock = entry->memblock;

		list_add(&entry->item,
			&blockpool->free_entry_list);
	}

	return memblock;
}

/*
 * __vxge_hw_blockpool_free - Frees the memory allcoated with
				__vxge_hw_blockpool_malloc
 */
void
__vxge_hw_blockpool_free(struct __vxge_hw_device *devh,
			void *memblock, u32 size,
			struct vxge_hw_mempool_dma *dma_object)
{
	struct __vxge_hw_blockpool_entry *entry = NULL;
	struct __vxge_hw_blockpool  *blockpool;

	blockpool = &devh->block_pool;

	if (!list_empty(&blockpool->free_entry_list))
		entry = (struct __vxge_hw_blockpool_entry *)
			list_entry((&blockpool->free_entry_list)->next,
				struct __vxge_hw_blockpool_entry,
				item);

	if (entry != NULL) {
		list_del(&entry->item);
		entry->length = size;
		entry->memblock = memblock;
		entry->dma_addr = dma_object->addr;
		entry->acc_handle = dma_object->acc_handle;
		entry->dma_handle = dma_object->handle;
		list_add(&entry->item,
			&blockpool->free_block_list);
	}

	return;
}

/*
 * __vxge_hw_blockpool_block_allocate - Allocates a block from block pool
 * This function allocates a block from block pool or from the system
 */
struct __vxge_hw_blockpool_entry *
__vxge_hw_blockpool_block_allocate(struct __vxge_hw_device *devh, u32 size)
{
	struct __vxge_hw_blockpool_entry *entry = NULL;
	struct __vxge_hw_blockpool  *blockpool;

	blockpool = &devh->block_pool;

	if (size == blockpool->block_size) {

		if (!list_empty(&blockpool->free_block_list))
			entry = (struct __vxge_hw_blockpool_entry *)
				list_entry((&blockpool->free_block_list)->next,
					struct __vxge_hw_blockpool_entry,
					item);

		if (entry != NULL)
			list_del(&entry->item);
	}

	return entry;
}

/*
 * __vxge_hw_blockpool_block_free - Frees a block from block pool
 * @devh: Hal device
 * @entry: Entry of block to be freed
 *
 * This function frees a block from block pool
 */
void
__vxge_hw_blockpool_block_free(struct __vxge_hw_device *devh,
			struct __vxge_hw_blockpool_entry *entry)
{
	struct __vxge_hw_blockpool  *blockpool;

	blockpool = &devh->block_pool;

	list_add(&entry->item, &blockpool->free_block_list);

	return;
}
