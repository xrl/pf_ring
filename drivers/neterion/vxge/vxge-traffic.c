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
 * vxge-traffic.c: Driver for Neterion Inc's X3100 Series 10GbE PCIe I/O
 *                 Virtualized Server Adapter.
 * Copyright(c) 2002-2010 Exar Corp.
 ******************************************************************************/
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/version.h>
#include <linux/pci.h>
#include <linux/inetdevice.h>
#include <linux/if_vlan.h>
#include <linux/vmalloc.h>

#include <net/tcp.h>

#include "vxge-traffic.h"
#include "vxge-config.h"
#include "vxge-main.h"

#ifdef CONFIG_NOT_COHERENT_CACHE
extern void flush_dcache_range(unsigned long start, unsigned long stop);
#endif

/*
 * vxge_hw_send_message - Send a unicast or broadcast message to other vpaths
 * @vpath: Virtual Path handle.
 * @msg_type: The type of message to send
 * @msg_dest: The destination vpath to send to (or) broadcast to all vpaths
 * @msg_data: 32 bits of data to associate with the message
 *
 * This method is called by the driver to send a message to another VPATH
 * for processing.
 *
 */
enum vxge_hw_status
vxge_hw_send_message(struct __vxge_hw_device *hldev, u64 vp_id, u8 msg_type,
			u8 msg_dest, u32 msg_data, u32 *msg_sent_to_vpaths)
{
	u64 data1 = 0ULL, data2 = 0ULL, steer_ctrl = 0ULL;
	u32 attempts = VXGE_HW_MSG_SEND_RETRY;
	enum vxge_hw_status status = VXGE_HW_OK;

	u32 fw_memo = VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL_FW_MEMO;

	data1 = VXGE_HW_RTS_ACCESS_STEER_DATA0_SEND_MSG_TYPE(msg_type) |
		VXGE_HW_RTS_ACCESS_STEER_DATA0_SEND_MSG_DEST(msg_dest) |
		VXGE_HW_RTS_ACCESS_STEER_DATA0_SEND_MSG_SRC(vp_id) |
		VXGE_HW_RTS_ACCESS_STEER_DATA0_SEND_MSG_DATA(msg_data);
	do {
		status = vxge_hw_vpath_fw_api(hldev, vp_id,
				VXGE_HW_RTS_ACCESS_STEER_CTRL_ACTION_SEND_MSG,
				0, fw_memo, &data1, &data2, &steer_ctrl);
		if (status != VXGE_HW_OK) {
			attempts--;
			if (attempts == 0) {
				return status;
			}
		}

	} while (status != VXGE_HW_OK);

	if (msg_sent_to_vpaths != NULL) {
		/* The API returns a vector of VPATHs the message
		 * was sent to in the event the destination is a
		 * broadcast message or being sent to the privileged VPATH
		 */
		*msg_sent_to_vpaths = data1 & VXGE_HW_MSG_SEND_TO_VPATH_MASK;
	}
	return status;
}

/*
 * vxge_hw_reenable_messages - Re-enable receiving messages after we receive one
 * @vpath: Virtual Path handle.
 *
 * This method is called by the driver to re-enable messages after receiving
 * a message. A driver can only receive one message at a time and it must
 * explictly re-enable receiving messages after it is done processing
 * the current one.
 * This is because message data is stored in the SRPCIM_TO_VPATH_WMSG register
 * and we don't want to trample this data until the driver is done with it.
 *
 */
void
vxge_hw_reenable_messages(struct __vxge_hw_virtualpath *vpath)
{
	struct vxge_hw_vpath_reg __iomem *vp_reg = vpath->vp_reg;
	writeq(VXGE_HW_MSG_ENABLE_ALL, &vp_reg->srpcim_msg_to_vpath_mask);
}

/*
 * vxge_hw_vpath_intr_enable - Enable vpath interrupts.
 * @vp: Virtual Path handle.
 *
 * Enable vpath interrupts. The function is to be executed the last in
 * vpath initialization sequence.
 *
 * See also: vxge_hw_vpath_intr_disable()
 */
enum vxge_hw_status vxge_hw_vpath_intr_enable(struct __vxge_hw_vpath_handle *vp)
{
	u64 val64;

	struct __vxge_hw_virtualpath *vpath;
	struct vxge_hw_vpath_reg __iomem *vp_reg;
	enum vxge_hw_status status = VXGE_HW_OK;
	if (vp == NULL) {
		status = VXGE_HW_ERR_INVALID_HANDLE;
		goto exit;
	}

	vpath = vp->vpath;

	if (vpath->vp_open == VXGE_HW_VP_NOT_OPEN) {
		status = VXGE_HW_ERR_VPATH_NOT_OPEN;
		goto exit;
	}

	vp_reg = vpath->vp_reg;

	writeq(VXGE_HW_INTR_MASK_ALL, &vp_reg->kdfcctl_errors_reg);

	__vxge_hw_pio_mem_write32_upper((u32)VXGE_HW_INTR_MASK_ALL,
			&vp_reg->general_errors_reg);

	__vxge_hw_pio_mem_write32_upper((u32)VXGE_HW_INTR_MASK_ALL,
			&vp_reg->pci_config_errors_reg);

	__vxge_hw_pio_mem_write32_upper((u32)VXGE_HW_INTR_MASK_ALL,
			&vp_reg->mrpcim_to_vpath_alarm_reg);

	__vxge_hw_pio_mem_write32_upper((u32)VXGE_HW_INTR_MASK_ALL,
			&vp_reg->srpcim_to_vpath_alarm_reg);

	__vxge_hw_pio_mem_write32_upper((u32)VXGE_HW_INTR_MASK_ALL,
			&vp_reg->vpath_ppif_int_status);

	__vxge_hw_pio_mem_write32_upper((u32)VXGE_HW_INTR_MASK_ALL,
			&vp_reg->srpcim_msg_to_vpath_reg);

	__vxge_hw_pio_mem_write32_upper((u32)VXGE_HW_INTR_MASK_ALL,
			&vp_reg->vpath_pcipif_int_status);

	__vxge_hw_pio_mem_write32_upper((u32)VXGE_HW_INTR_MASK_ALL,
			&vp_reg->prc_alarm_reg);

	__vxge_hw_pio_mem_write32_upper((u32)VXGE_HW_INTR_MASK_ALL,
			&vp_reg->wrdma_alarm_status);

	__vxge_hw_pio_mem_write32_upper((u32)VXGE_HW_INTR_MASK_ALL,
			&vp_reg->asic_ntwk_vp_err_reg);

	__vxge_hw_pio_mem_write32_upper((u32)VXGE_HW_INTR_MASK_ALL,
			&vp_reg->xgmac_vp_int_status);

	val64 = readq(&vp_reg->vpath_general_int_status);

	/* Mask unwanted interrupts */

	__vxge_hw_pio_mem_write32_upper((u32)VXGE_HW_INTR_MASK_ALL,
			&vp_reg->vpath_pcipif_int_mask);

	__vxge_hw_pio_mem_write32_upper((u32)VXGE_HW_INTR_MASK_ALL,
			&vp_reg->srpcim_msg_to_vpath_mask);

	__vxge_hw_pio_mem_write32_upper((u32)VXGE_HW_INTR_MASK_ALL,
			&vp_reg->srpcim_to_vpath_alarm_mask);

	__vxge_hw_pio_mem_write32_upper((u32)VXGE_HW_INTR_MASK_ALL,
			&vp_reg->mrpcim_to_vpath_alarm_mask);

	__vxge_hw_pio_mem_write32_upper((u32)VXGE_HW_INTR_MASK_ALL,
			&vp_reg->pci_config_errors_mask);

	/* Unmask the individual interrupts */

	writeq((u32)vxge_bVALn((VXGE_HW_GENERAL_ERRORS_REG_DBLGEN_FIFO1_OVRFLOW|
		VXGE_HW_GENERAL_ERRORS_REG_DBLGEN_FIFO2_OVRFLOW|
		VXGE_HW_GENERAL_ERRORS_REG_STATSB_DROP_TIMEOUT_REQ|
		VXGE_HW_GENERAL_ERRORS_REG_STATSB_PIF_CHAIN_ERR), 0, 32),
		&vp_reg->general_errors_mask);

	__vxge_hw_pio_mem_write32_upper(
		(u32)vxge_bVALn((VXGE_HW_KDFCCTL_ERRORS_REG_KDFCCTL_FIFO1_OVRWR|
		VXGE_HW_KDFCCTL_ERRORS_REG_KDFCCTL_FIFO2_OVRWR|
		VXGE_HW_KDFCCTL_ERRORS_REG_KDFCCTL_FIFO1_POISON|
		VXGE_HW_KDFCCTL_ERRORS_REG_KDFCCTL_FIFO2_POISON|
		VXGE_HW_KDFCCTL_ERRORS_REG_KDFCCTL_FIFO1_DMA_ERR|
		VXGE_HW_KDFCCTL_ERRORS_REG_KDFCCTL_FIFO2_DMA_ERR), 0, 32),
		&vp_reg->kdfcctl_errors_mask);

	__vxge_hw_pio_mem_write32_upper(0, &vp_reg->vpath_ppif_int_mask);

	__vxge_hw_pio_mem_write32_upper(
		(u32)vxge_bVALn(VXGE_HW_PRC_ALARM_REG_PRC_RING_BUMP, 0, 32),
		&vp_reg->prc_alarm_mask);

	__vxge_hw_pio_mem_write32_upper(0, &vp_reg->wrdma_alarm_mask);
	__vxge_hw_pio_mem_write32_upper(0, &vp_reg->xgmac_vp_int_mask);

	if (vpath->hldev->first_vp_id != vpath->vp_id)
		__vxge_hw_pio_mem_write32_upper((u32)VXGE_HW_INTR_MASK_ALL,
			&vp_reg->asic_ntwk_vp_err_mask);
	else
		__vxge_hw_pio_mem_write32_upper((u32)vxge_bVALn((
		VXGE_HW_ASIC_NTWK_VP_ERR_REG_XMACJ_NTWK_REAFFIRMED_FAULT |
		VXGE_HW_ASIC_NTWK_VP_ERR_REG_XMACJ_NTWK_REAFFIRMED_OK), 0, 32),
		&vp_reg->asic_ntwk_vp_err_mask);

	__vxge_hw_pio_mem_write32_upper(0,
		&vp_reg->vpath_general_int_mask);
exit:
	return status;

}

/*
 * vxge_hw_vpath_intr_disable - Disable vpath interrupts.
 * @vp: Virtual Path handle.
 *
 * Disable vpath interrupts. The function is to be executed the last in
 * vpath initialization sequence.
 *
 * See also: vxge_hw_vpath_intr_enable()
 */
enum vxge_hw_status vxge_hw_vpath_intr_disable(
			struct __vxge_hw_vpath_handle *vp)
{
	u64 val64;

	struct __vxge_hw_virtualpath *vpath;
	enum vxge_hw_status status = VXGE_HW_OK;
	struct vxge_hw_vpath_reg __iomem *vp_reg;
	if (vp == NULL) {
		status = VXGE_HW_ERR_INVALID_HANDLE;
		goto exit;
	}

	vpath = vp->vpath;

	if (vpath->vp_open == VXGE_HW_VP_NOT_OPEN) {
		status = VXGE_HW_ERR_VPATH_NOT_OPEN;
		goto exit;
	}
	vp_reg = vpath->vp_reg;

	__vxge_hw_pio_mem_write32_upper(
		(u32)VXGE_HW_INTR_MASK_ALL,
		&vp_reg->vpath_general_int_mask);

	val64 = VXGE_HW_TIM_CLR_INT_EN_VP(1 << (16 - vpath->vp_id));

	writeq(VXGE_HW_INTR_MASK_ALL, &vp_reg->kdfcctl_errors_mask);

	__vxge_hw_pio_mem_write32_upper((u32)VXGE_HW_INTR_MASK_ALL,
			&vp_reg->general_errors_mask);

	__vxge_hw_pio_mem_write32_upper((u32)VXGE_HW_INTR_MASK_ALL,
			&vp_reg->pci_config_errors_mask);

	__vxge_hw_pio_mem_write32_upper((u32)VXGE_HW_INTR_MASK_ALL,
			&vp_reg->mrpcim_to_vpath_alarm_mask);

	__vxge_hw_pio_mem_write32_upper((u32)VXGE_HW_INTR_MASK_ALL,
			&vp_reg->srpcim_to_vpath_alarm_mask);

	__vxge_hw_pio_mem_write32_upper((u32)VXGE_HW_INTR_MASK_ALL,
			&vp_reg->vpath_ppif_int_mask);

	__vxge_hw_pio_mem_write32_upper((u32)VXGE_HW_INTR_MASK_ALL,
			&vp_reg->srpcim_msg_to_vpath_mask);

	__vxge_hw_pio_mem_write32_upper((u32)VXGE_HW_INTR_MASK_ALL,
			&vp_reg->vpath_pcipif_int_mask);

	__vxge_hw_pio_mem_write32_upper((u32)VXGE_HW_INTR_MASK_ALL,
			&vp_reg->wrdma_alarm_mask);

	__vxge_hw_pio_mem_write32_upper((u32)VXGE_HW_INTR_MASK_ALL,
			&vp_reg->prc_alarm_mask);

	__vxge_hw_pio_mem_write32_upper((u32)VXGE_HW_INTR_MASK_ALL,
			&vp_reg->xgmac_vp_int_mask);

	__vxge_hw_pio_mem_write32_upper((u32)VXGE_HW_INTR_MASK_ALL,
			&vp_reg->asic_ntwk_vp_err_mask);

exit:
	return status;
}

void
vxge_hw_vpath_dynamic_rti_ci_set(struct __vxge_hw_ring *ring)
{
	u64 val64 = ring->tim_rti_cfg1_saved;

	val64 |= VXGE_HW_TIM_CFG1_INT_NUM_TIMER_CI;
	ring->tim_rti_cfg1_saved = val64;
	writeq(val64, &ring->vp_reg->tim_cfg1_int_num[
				VXGE_HW_VPATH_INTR_RX]);

	return;
}

void
vxge_hw_vpath_dynamic_rti_ci_reset(struct __vxge_hw_ring *ring)
{
	u64 val64 = ring->tim_rti_cfg1_saved;

	val64 &= ~VXGE_HW_TIM_CFG1_INT_NUM_TIMER_CI;
	ring->tim_rti_cfg1_saved = val64;
	writeq(val64, &ring->vp_reg->tim_cfg1_int_num[
				VXGE_HW_VPATH_INTR_RX]);

	return;
}

void
vxge_hw_vpath_dynamic_tti_btimer_set(struct __vxge_hw_fifo *fifo)
{
	u64 val64 = fifo->tim_tti_cfg1_saved;
	u64 timer = (fifo->btimer * 1000)/272;

	val64 &= ~VXGE_HW_TIM_CFG1_INT_NUM_BTIMER_VAL(0x3ffffff);
	val64 |= VXGE_HW_TIM_CFG1_INT_NUM_BTIMER_VAL(timer);
	writeq(val64, &fifo->vp_reg->tim_cfg1_int_num[
		VXGE_HW_VPATH_INTR_TX]);
	fifo->tim_tti_cfg1_saved = val64;
	return;
}

void
vxge_hw_vpath_dynamic_tti_rtimer_set(struct __vxge_hw_fifo *fifo)
{
	u64 val64 = fifo->tim_tti_cfg3_saved;
	u64 timer = (fifo->rtimer * 1000)/272;

	val64 &= ~VXGE_HW_TIM_CFG3_INT_NUM_RTIMER_VAL(0x3ffffff);
	if (timer)
		val64 |= VXGE_HW_TIM_CFG3_INT_NUM_RTIMER_VAL(timer) |
			VXGE_HW_TIM_CFG3_INT_NUM_RTIMER_EVENT_SF(5);

	writeq(val64, &fifo->vp_reg->tim_cfg3_int_num[
		VXGE_HW_VPATH_INTR_TX]);
	/* tti_cfg3_saved is not updated again because it is
	   initialized at one place only - init time.
	 */
	return;
}

void
vxge_hw_vpath_dynamic_rti_btimer_set(struct __vxge_hw_ring *ring)
{
	u64 val64 = ring->tim_rti_cfg1_saved;
	u64 timer = (ring->btimer * 1000)/272;

	val64 &= ~VXGE_HW_TIM_CFG1_INT_NUM_BTIMER_VAL(0x3ffffff);
	val64 |= VXGE_HW_TIM_CFG1_INT_NUM_BTIMER_VAL(timer);
	writeq(val64, &ring->vp_reg->tim_cfg1_int_num[
		VXGE_HW_VPATH_INTR_RX]);
	ring->tim_rti_cfg1_saved = val64;
	return;
}

void
vxge_hw_vpath_dynamic_rti_rtimer_set(struct __vxge_hw_ring *ring)
{
	u64 val64 = ring->tim_rti_cfg3_saved;
	u64 timer = (ring->rtimer * 1000)/272;

	val64 &= ~VXGE_HW_TIM_CFG3_INT_NUM_RTIMER_VAL(0x3ffffff);
	if (timer)
		val64 |= VXGE_HW_TIM_CFG3_INT_NUM_RTIMER_VAL(timer) |
			VXGE_HW_TIM_CFG3_INT_NUM_RTIMER_EVENT_SF(4);

	writeq(val64, &ring->vp_reg->tim_cfg3_int_num[
		VXGE_HW_VPATH_INTR_RX]);
	/* rti_cfg3_saved is not updated again because it is
	   initialized at one place only - init time.
	 */
	return;
}

/**
 * vxge_hw_channel_msix_mask - Mask MSIX Vector.
 * @channeh: Channel for rx or tx handle
 * @msix_id:  MSIX ID
 *
 * The function masks the msix interrupt for the given msix_id.
 * As an additional note, this function is only called from the napi handler.
 * The read operation to flush the write to mask the interrupt vector is done
 * instead of a barrier to ensure that the posted write goes on the bus but is
 * also received by the device.
 *
 * Returns: 0
 */
void vxge_hw_channel_msix_mask(struct __vxge_hw_channel *channel, int msix_id)
{
	u32 val32;

	__vxge_hw_pio_mem_write32_upper(
		(u32) vxge_bVALn(vxge_mBIT(msix_id >> 2), 0, 32),
		&channel->common_reg->set_msix_mask_vect[msix_id%4]);

	val32 = readl(&channel->common_reg->titan_general_int_status);

	return;
}

/**
 * vxge_hw_channel_msix_unmask - Unmask the MSIX Vector.
 * @channeh: Channel for rx or tx handle
 * @msix_id:  MSI ID
 *
 * The function unmasks the msix interrupt for the given msix_id
 *
 * Returns: 0
 */
void
vxge_hw_channel_msix_unmask(struct __vxge_hw_channel *channel, int msix_id)
{
	__vxge_hw_pio_mem_write32_upper(
		(u32)vxge_bVALn(vxge_mBIT(msix_id >> 2), 0, 32),
		&channel->common_reg->clear_msix_mask_vect[msix_id%4]);

	return;
}

/**
 * vxge_hw_channel_msix_clear - Unmask the MSIX Vector.
 * @channeh: Channel for rx or tx handle
 * @msix_id:  MSI ID
 *
 * The function unmasks the msix interrupt for the given msix_id
 * if configured in MSIX oneshot mode
 *
 * Returns: 0
 */
void
vxge_hw_channel_msix_clear(struct __vxge_hw_channel *channel, int msix_id)
{
	__vxge_hw_pio_mem_write32_upper(
		(u32)vxge_bVALn(vxge_mBIT(msix_id >> 2), 0, 32),
		&channel->common_reg->clr_msix_one_shot_vec[msix_id%4]);

	return;
}

/**
 * vxge_hw_device_set_intr_type - Updates the configuration
 *		with new interrupt type.
 * @hldev: HW device handle.
 * @intr_mode: New interrupt type
 */
u32 vxge_hw_device_set_intr_type(struct __vxge_hw_device *hldev, u32 intr_mode)
{

	if (

	(intr_mode != VXGE_HW_INTR_MODE_IRQLINE) &&
	(intr_mode != VXGE_HW_INTR_MODE_MSIX) &&
	(intr_mode != VXGE_HW_INTR_MODE_MSIX_ONE_SHOT) &&
	(intr_mode != VXGE_HW_INTR_MODE_DEF))
		intr_mode = VXGE_HW_INTR_MODE_IRQLINE;

	hldev->config.intr_mode = intr_mode;
	return intr_mode;
}

/**
 * vxge_hw_device_intr_enable - Enable interrupts.
 * @hldev: HW device handle.
 * @op: One of the enum vxge_hw_device_intr enumerated values specifying
 *      the type(s) of interrupts to enable.
 *
 * Enable Titan interrupts. The function is to be executed the last in
 * Titan initialization sequence.
 *
 * See also: vxge_hw_device_intr_disable()
 */
void vxge_hw_device_intr_enable(struct __vxge_hw_device *hldev)
{
	u32 i;
	u64 val64;
	u32 val32;

	vxge_hw_device_mask_all(hldev);

	for (i = 0; i < VXGE_HW_MAX_VIRTUAL_PATHS; i++) {

		if (!(hldev->vpaths_deployed & vxge_mBIT(i)))
			continue;

		vxge_hw_vpath_intr_enable(
			VXGE_HW_VIRTUAL_PATH_HANDLE(&hldev->virtual_paths[i]));
	}

	if (

	(hldev->config.intr_mode == VXGE_HW_INTR_MODE_IRQLINE)) {
		val64 = hldev->tim_int_mask0[VXGE_HW_VPATH_INTR_TX] |
			hldev->tim_int_mask0[VXGE_HW_VPATH_INTR_RX];

		if (val64 != 0) {
			writeq(val64, &hldev->common_reg->tim_int_status0);

			writeq(~val64, &hldev->common_reg->tim_int_mask0);
		}

		val32 = hldev->tim_int_mask1[VXGE_HW_VPATH_INTR_TX] |
			hldev->tim_int_mask1[VXGE_HW_VPATH_INTR_RX];

		if (val32 != 0) {
			__vxge_hw_pio_mem_write32_upper(val32,
					&hldev->common_reg->tim_int_status1);

			__vxge_hw_pio_mem_write32_upper(~val32,
					&hldev->common_reg->tim_int_mask1);
		}
	}

	val64 = readq(&hldev->common_reg->titan_general_int_status);

	vxge_hw_device_unmask_all(hldev);

	return;
}

/**
 * vxge_hw_device_intr_disable - Disable Titan interrupts.
 * @hldev: HW device handle.
 * @op: One of the enum vxge_hw_device_intr enumerated values specifying
 *      the type(s) of interrupts to disable.
 *
 * Disable Titan interrupts.
 *
 * See also: vxge_hw_device_intr_enable()
 */
void vxge_hw_device_intr_disable(struct __vxge_hw_device *hldev)
{
	u32 i;

	vxge_hw_device_mask_all(hldev);

	/* mask all the tim interrupts */
	writeq(VXGE_HW_INTR_MASK_ALL, &hldev->common_reg->tim_int_mask0);
	__vxge_hw_pio_mem_write32_upper(VXGE_HW_DEFAULT_32,
		&hldev->common_reg->tim_int_mask1);

	for (i = 0; i < VXGE_HW_MAX_VIRTUAL_PATHS; i++) {

		if (!(hldev->vpaths_deployed & vxge_mBIT(i)))
			continue;

		vxge_hw_vpath_intr_disable(
			VXGE_HW_VIRTUAL_PATH_HANDLE(&hldev->virtual_paths[i]));
	}

	return;
}

/**
 * vxge_hw_device_mask_all - Mask all device interrupts.
 * @hldev: HW device handle.
 *
 * Mask	all device interrupts.
 *
 * See also: vxge_hw_device_unmask_all()
 */
void vxge_hw_device_mask_all(struct __vxge_hw_device *hldev)
{
	u64 val64;

	val64 = VXGE_HW_TITAN_MASK_ALL_INT_ALARM |
		VXGE_HW_TITAN_MASK_ALL_INT_TRAFFIC;

	__vxge_hw_pio_mem_write32_upper((u32)vxge_bVALn(val64, 0, 32),
				&hldev->common_reg->titan_mask_all_int);

	return;
}

/**
 * vxge_hw_device_unmask_all - Unmask all device interrupts.
 * @hldev: HW device handle.
 *
 * Unmask all device interrupts.
 *
 * See also: vxge_hw_device_mask_all()
 */
void vxge_hw_device_unmask_all(struct __vxge_hw_device *hldev)
{
	u64 val64 = 0;

	if (hldev->config.intr_mode == VXGE_HW_INTR_MODE_IRQLINE)
		val64 =  VXGE_HW_TITAN_MASK_ALL_INT_TRAFFIC;

	__vxge_hw_pio_mem_write32_upper((u32)vxge_bVALn(val64, 0, 32),
			&hldev->common_reg->titan_mask_all_int);

	return;
}

/**
 * vxge_hw_device_flush_io - Flush io writes.
 * @hldev: HW device handle.
 *
 * The function	performs a read operation to flush io writes.
 *
 * Returns: void
 */
void vxge_hw_device_flush_io(struct __vxge_hw_device *hldev)
{
	u32 val32;

	val32 = readl(&hldev->common_reg->titan_general_int_status);
}

/**
 * vxge_hw_device_begin_irq - Begin IRQ processing.
 * @hldev: HW device handle.
 * @skip_alarms: Do not clear the alarms
 * @reason: "Reason" for the interrupt, the value of Titan's
 *	general_int_status register.
 *
 * The function	performs two actions, It first checks whether (shared IRQ) the
 * interrupt was raised	by the device. Next, it	masks the device interrupts.
 *
 * Note:
 * vxge_hw_device_begin_irq() does not flush MMIO writes through the
 * bridge. Therefore, two back-to-back interrupts are potentially possible.
 *
 * Returns: 0, if the interrupt	is not "ours" (note that in this case the
 * device remain enabled).
 * Otherwise, vxge_hw_device_begin_irq() returns 64bit general adapter
 * status.
 */
enum vxge_hw_status vxge_hw_device_begin_irq(struct __vxge_hw_device *hldev,
					     u32 skip_alarms, u64 *reason)
{
	u32 i;
	u64 val64;
	u64 adapter_status;
	u64 vpath_mask;
	enum vxge_hw_status ret = VXGE_HW_OK;

	val64 = readq(&hldev->common_reg->titan_general_int_status);

	if (unlikely(!val64)) {
		/* not Titan interrupt	*/
		*reason	= 0;
		ret = VXGE_HW_ERR_WRONG_IRQ;
		goto exit;
	}

	if (unlikely(val64 == VXGE_HW_ALL_FOXES)) {

		adapter_status = readq(&hldev->common_reg->adapter_status);

		if (adapter_status == VXGE_HW_ALL_FOXES) {

			__vxge_hw_device_handle_error(hldev,
				NULL_VPID, VXGE_HW_EVENT_SLOT_FREEZE);
			*reason	= 0;
			ret = VXGE_HW_ERR_SLOT_FREEZE;
			goto exit;
		}
	}

	hldev->stats.sw_dev_info_stats.total_intr_cnt++;

	*reason	= val64;

	vpath_mask = hldev->vpaths_deployed >>
				(64 - VXGE_HW_MAX_VIRTUAL_PATHS);

	if (val64 &
	    VXGE_HW_TITAN_GENERAL_INT_STATUS_VPATH_TRAFFIC_INT(vpath_mask)) {
		hldev->stats.sw_dev_info_stats.traffic_intr_cnt++;

		return VXGE_HW_OK;
	}

	hldev->stats.sw_dev_info_stats.not_traffic_intr_cnt++;

	if (unlikely((val64 &
		VXGE_HW_TITAN_GENERAL_INT_STATUS_VPATH_ALARM_INT) > 0)) {

		enum vxge_hw_status error_level = VXGE_HW_OK;

		hldev->stats.sw_dev_err_stats.vpath_alarms++;

		for (i = 0; i < VXGE_HW_MAX_VIRTUAL_PATHS; i++) {

			if (!(hldev->vpaths_deployed & vxge_mBIT(i)))
				continue;

			ret = __vxge_hw_vpath_alarm_process(
				&hldev->virtual_paths[i], skip_alarms);

			error_level = max(ret, error_level);

			if (unlikely((ret == VXGE_HW_ERR_CRITICAL) ||
				(ret == VXGE_HW_ERR_SLOT_FREEZE)))
				break;
		}

		ret = error_level;
	}
exit:
	return ret;
}

/*
 * __vxge_hw_device_handle_link_up_ind
 * @hldev: HW device handle.
 *
 * Link up indication handler. The function is invoked by HW when
 * Titan indicates that the link is up for programmable amount of time.
 */
enum vxge_hw_status
__vxge_hw_device_handle_link_up_ind(struct __vxge_hw_device *hldev)
{
	/*
	 * If the previous link state is not down, return.
	 */
	if (hldev->link_state == VXGE_HW_LINK_UP)
		goto exit;

	hldev->link_state = VXGE_HW_LINK_UP;

	/* notify driver */
	if (hldev->uld_callbacks.link_up)
		hldev->uld_callbacks.link_up(hldev);
exit:
	return VXGE_HW_OK;
}

/*
 * __vxge_hw_device_handle_link_down_ind
 * @hldev: HW device handle.
 *
 * Link down indication handler. The function is invoked by HW when
 * Titan indicates that the link is down.
 */
enum vxge_hw_status
__vxge_hw_device_handle_link_down_ind(struct __vxge_hw_device *hldev)
{
	/*
	 * If the previous link state is not down, return.
	 */
	if (hldev->link_state == VXGE_HW_LINK_DOWN)
		goto exit;

	hldev->link_state = VXGE_HW_LINK_DOWN;

	/* notify driver */
	if (hldev->uld_callbacks.link_down)
		hldev->uld_callbacks.link_down(hldev);
exit:
	return VXGE_HW_OK;
}

/**
 * __vxge_hw_device_handle_error - Handle error
 * @hldev: HW device
 * @vp_id: Vpath Id
 * @type: Error type. Please see enum vxge_hw_event{}
 *
 * Handle error.
 */
enum vxge_hw_status
__vxge_hw_device_handle_error(
		struct __vxge_hw_device *hldev,
		u32 vp_id,
		enum vxge_hw_event type)
{
	switch (type) {
	case VXGE_HW_EVENT_UNKNOWN:
		break;
	case VXGE_HW_EVENT_RESET_START:
	case VXGE_HW_EVENT_RESET_COMPLETE:
	case VXGE_HW_EVENT_LINK_DOWN:
	case VXGE_HW_EVENT_LINK_UP:
		goto out;
	case VXGE_HW_EVENT_ALARM_CLEARED:
		goto out;
	case VXGE_HW_EVENT_ECCERR:
	case VXGE_HW_EVENT_MRPCIM_ECCERR:
		goto out;
	case VXGE_HW_EVENT_FIFO_ERR:
	case VXGE_HW_EVENT_VPATH_ERR:
	case VXGE_HW_EVENT_CRITICAL_ERR:
	case VXGE_HW_EVENT_SERR:
		break;
	case VXGE_HW_EVENT_SRPCIM_SERR:
	case VXGE_HW_EVENT_MRPCIM_SERR:
		goto out;
	case VXGE_HW_EVENT_SLOT_FREEZE:
		break;
	default:
		vxge_assert(0);
		goto out;
	}

	/* notify driver */
	if (hldev->uld_callbacks.crit_err)
		hldev->uld_callbacks.crit_err(
			(struct __vxge_hw_device *)hldev,
			type, vp_id);
out:

	return VXGE_HW_OK;
}

/**
 * vxge_hw_device_clear_tx_rx - Acknowledge (that is, clear) the
 * condition that has caused the Tx and RX interrupt.
 * @hldev: HW device.
 *
 * Acknowledge (that is, clear) the condition that has caused
 * the Tx and Rx interrupt.
 * See also: vxge_hw_device_begin_irq(),
 * vxge_hw_device_mask_tx_rx(), vxge_hw_device_unmask_tx_rx().
 */
void vxge_hw_device_clear_tx_rx(struct __vxge_hw_device *hldev)
{

	if ((hldev->tim_int_mask0[VXGE_HW_VPATH_INTR_TX] != 0) ||
	   (hldev->tim_int_mask0[VXGE_HW_VPATH_INTR_RX] != 0)) {
		writeq((hldev->tim_int_mask0[VXGE_HW_VPATH_INTR_TX] |
				 hldev->tim_int_mask0[VXGE_HW_VPATH_INTR_RX]),
				&hldev->common_reg->tim_int_status0);
	}

	if ((hldev->tim_int_mask1[VXGE_HW_VPATH_INTR_TX] != 0) ||
	   (hldev->tim_int_mask1[VXGE_HW_VPATH_INTR_RX] != 0)) {
		__vxge_hw_pio_mem_write32_upper(
				(hldev->tim_int_mask1[VXGE_HW_VPATH_INTR_TX] |
				 hldev->tim_int_mask1[VXGE_HW_VPATH_INTR_RX]),
				&hldev->common_reg->tim_int_status1);
	}

	return;
}

/*
 * vxge_hw_channel_dtr_alloc - Allocate a dtr from the channel
 * @channel: Channel
 * @dtrh: Buffer to return the DTR pointer
 *
 * Allocates a dtr from the reserve array. If the reserve array is empty,
 * it swaps the reserve and free arrays.
 *
 */
enum vxge_hw_status
vxge_hw_channel_dtr_alloc(struct __vxge_hw_channel *channel, void **dtrh)
{

	if (channel->free_count) {
		channel->free_count--;
		*dtrh =	channel->dtr_arr[--channel->alloc_index];
		if (channel->alloc_index == 0)
			channel->alloc_index = channel->length;
 		return VXGE_HW_OK;
 	}
	channel->stats->full_cnt++;

	*dtrh =	NULL;
	return VXGE_HW_INF_OUT_OF_DESCRIPTORS;
}

/*
 * vxge_hw_channel_dtr_post - Post a dtr to the channel
 * @channelh: Channel
 * @dtrh: DTR pointer
 *
 * Posts a dtr to work array.
 *
 */
void vxge_hw_channel_dtr_post(struct __vxge_hw_channel *channel, void *dtrh)
{
	vxge_assert(channel->post_count < channel->length);
	channel->post_count++;
}

/*
 * vxge_hw_channel_dtr_try_complete - Returns next completed dtr
 * @channel: Channel
 * @dtr: Buffer to return the next completed DTR pointer
 *
 * Returns the next completed dtr with out removing it from work array
 *
 */
void
vxge_hw_channel_dtr_try_complete(struct __vxge_hw_channel *channel, void **dtrh)
{
	vxge_assert(channel->compl_index <= channel->length);
	vxge_assert(channel->compl_index);
	if (channel->post_count) {
		*dtrh =	channel->dtr_arr[channel->compl_index - 1];
		prefetch(*dtrh);
	}
	else
		*dtrh = NULL;
}

/*
 * vxge_hw_channel_dtr_complete - Removes next completed dtr from the work array
 * @channel: Channel handle
 *
 * Removes the next completed dtr from work array
 *
 */
void vxge_hw_channel_dtr_complete(struct __vxge_hw_channel *channel)
{

	vxge_assert(channel->post_count);
	vxge_assert(channel->compl_index);
	channel->compl_index--;
	/* wrap-around */
	if (channel->compl_index == 0)
		channel->compl_index = channel->length;
	channel->post_count--;
	vxge_assert(channel->post_count < channel->length);
	vxge_assert(channel->free_count <= channel->length);
	channel->stats->total_compl_cnt++;
}

/*
 * vxge_hw_channel_dtr_free - Frees a dtr
 * @channel: Channel handle
 * @dtr:  DTR pointer
 *
 * Returns the dtr to free array
 *
 */
void vxge_hw_channel_dtr_free(struct __vxge_hw_channel *channel, void *dtrh)
{
	vxge_assert(channel->free_count < channel->length);
	channel->free_count++;
}

/*
 * vxge_hw_channel_dtr_count
 * @channel: Channel handle. Obtained via vxge_hw_channel_open().
 *
 * Retreive number of DTRs available. This function can not be called
 * from data path. ring_initial_replenishi() is the only user.
 */
int vxge_hw_channel_dtr_count(struct __vxge_hw_channel *channel)
{
	return (channel->free_count);
}

/**
 * vxge_hw_ring_rxd_reserve	- Reserve ring descriptor.
 * @ring: Handle to the ring object used for receive
 * @rxdh: Reserved descriptor. On success HW fills this "out" parameter
 * with a valid handle.
 *
 * Reserve Rx descriptor for the subsequent filling-in driver
 * and posting on the corresponding channel (@channelh)
 * via vxge_hw_ring_rxd_post().
 *
 * Returns: VXGE_HW_OK - success.
 * VXGE_HW_INF_OUT_OF_DESCRIPTORS - Currently no descriptors available.
 *
 */
enum vxge_hw_status vxge_hw_ring_rxd_reserve(struct __vxge_hw_ring *ring,
	void **rxdh)
{
	enum vxge_hw_status status;

	status = vxge_hw_channel_dtr_alloc(&ring->channel, rxdh);

	if (status == VXGE_HW_OK) {
		struct vxge_hw_ring_rxd_1 *rxdp =
			(struct vxge_hw_ring_rxd_1 *)*rxdh;

		rxdp->control_0	= rxdp->control_1 = 0;
	}

	return status;
}

/**
 * vxge_hw_ring_rxd_free - Free descriptor.
 * @ring: Handle to the ring object used for receive
 * @rxdh: Descriptor handle.
 *
 * Free	the reserved descriptor. This operation is "symmetrical" to
 * vxge_hw_ring_rxd_reserve. The "free-ing" completes the descriptor's
 * lifecycle.
 *
 * After free-ing (see vxge_hw_ring_rxd_free()) the descriptor again can
 * be:
 *
 * - reserved (vxge_hw_ring_rxd_reserve);
 *
 * - posted	(vxge_hw_ring_rxd_post);
 *
 * - completed (vxge_hw_ring_rxd_next_completed);
 *
 * - and recycled again	(vxge_hw_ring_rxd_free).
 *
 * For alternative state transitions and more details please refer to
 * the design doc.
 *
 */
void vxge_hw_ring_rxd_free(struct __vxge_hw_ring *ring, void *rxdh)
{
	vxge_hw_channel_dtr_free(&ring->channel, rxdh);
}

/**
 * vxge_hw_ring_rxd_pre_post - Prepare rxd and post
 * @ring: Handle to the ring object used for receive
 * @rxdh: Descriptor handle.
 *
 * This routine prepares a rxd and posts
 */
void vxge_hw_ring_rxd_pre_post(struct __vxge_hw_ring *ring, void *rxdh)
{
	vxge_hw_channel_dtr_post(&ring->channel, rxdh);
}

/**
 * vxge_hw_ring_rxd_post_post - Process rxd after post.
 * @ring: Handle to the ring object used for receive
 * @rxdh: Descriptor handle.
 *
 * Processes rxd after post
 */
void vxge_hw_ring_rxd_post_post(struct __vxge_hw_ring *ring, void *rxdh)
{
	struct vxge_hw_ring_rxd_1 *rxdp = (struct vxge_hw_ring_rxd_1 *)rxdh;

	rxdp->control_0	= VXGE_HW_RING_RXD_LIST_OWN_ADAPTER;

	if (ring->stats->common_stats.usage_cnt > 0)
		ring->stats->common_stats.usage_cnt--;
}

/**
 * vxge_hw_ring_rxd_post - Post descriptor on the ring.
 * @ring: Handle to the ring object used for receive
 * @rxdh: Descriptor obtained via vxge_hw_ring_rxd_reserve().
 *
 * Post	descriptor on the ring.
 * Prior to posting the	descriptor should be filled in accordance with
 * Host/Titan interface specification for a given service (LL, etc.).
 *
 */
void vxge_hw_ring_rxd_post(struct __vxge_hw_ring *ring, void *rxdh)
{
	struct vxge_hw_ring_rxd_1 *rxdp = (struct vxge_hw_ring_rxd_1 *)rxdh;

	wmb();
	rxdp->control_0	= VXGE_HW_RING_RXD_LIST_OWN_ADAPTER;

	vxge_hw_channel_dtr_post(&ring->channel, rxdh);

	if (ring->stats->common_stats.usage_cnt > 0)
		ring->stats->common_stats.usage_cnt--;
}

/**
 * vxge_hw_ring_rxd_post_post_wmb - Process rxd after post with memory barrier.
 * @ring: Handle to the ring object used for receive
 * @rxdh: Descriptor handle.
 *
 * Processes rxd after post with memory barrier.
 */
void vxge_hw_ring_rxd_post_post_wmb(struct __vxge_hw_ring *ring, void *rxdh)
{
	wmb();
	vxge_hw_ring_rxd_post_post(ring, rxdh);
}

/**
 * vxge_hw_ring_rxd_next_completed - Get the _next_ completed descriptor.
 * @ring: Handle to the ring object used for receive
 * @rxdh: Descriptor handle. Returned by HW.
 * @t_code:	Transfer code, as per Titan User Guide,
 *	 Receive Descriptor Format. Returned by HW.
 *
 * Retrieve the	_next_ completed descriptor.
 * HW uses ring callback (*vxge_hw_ring_callback_f) to notifiy
 * driver of new completed descriptors. After that
 * the driver can use vxge_hw_ring_rxd_next_completed to retrieve the rest
 * completions (the very first completion is passed by HW via
 * vxge_hw_ring_callback_f).
 *
 * Implementation-wise, the driver is free to call
 * vxge_hw_ring_rxd_next_completed either immediately from inside the
 * ring callback, or in a deferred fashion and separate (from HW)
 * context.
 *
 * Non-zero @t_code means failure to fill-in receive buffer(s)
 * of the descriptor.
 * For instance, parity	error detected during the data transfer.
 * In this case	Titan will complete the descriptor and indicate
 * for the host	that the received data is not to be used.
 * For details please refer to Titan User Guide.
 *
 * Returns: VXGE_HW_OK - success.
 * VXGE_HW_INF_NO_MORE_COMPLETED_DESCRIPTORS - No completed descriptors
 * are currently available for processing.
 *
 * See also: vxge_hw_ring_callback_f{},
 * vxge_hw_fifo_rxd_next_completed(), enum vxge_hw_status{}.
 */
enum vxge_hw_status vxge_hw_ring_rxd_next_completed(
	struct __vxge_hw_ring *ring, void **rxdh, u8 *t_code)
{
	struct __vxge_hw_channel *channel;
	struct vxge_hw_ring_rxd_1 *rxdp;
	enum vxge_hw_status status = VXGE_HW_OK;
	u64 control_0;
	u64 own;

	channel = &ring->channel;

	vxge_hw_channel_dtr_try_complete(channel, rxdh);

	rxdp = (struct vxge_hw_ring_rxd_1 *)*rxdh;
	if (rxdp == NULL) {
		status = VXGE_HW_INF_NO_MORE_COMPLETED_DESCRIPTORS;
		goto exit;
	}

	control_0 = rxdp->control_0;
	own = control_0 & VXGE_HW_RING_RXD_LIST_OWN_ADAPTER;
	*t_code	= (u8)VXGE_HW_RING_RXD_T_CODE_GET(control_0);

	/* check whether it is not the end */
	if (!own || ((*t_code == VXGE_HW_RING_T_CODE_FRM_DROP) && own)) {

		vxge_assert(((struct vxge_hw_ring_rxd_1 *)rxdp)->host_control !=
				0);

		vxge_hw_channel_dtr_complete(channel);

		vxge_assert(*t_code != VXGE_HW_RING_RXD_T_CODE_UNUSED);

		ring->stats->common_stats.usage_cnt++;
		if (ring->stats->common_stats.usage_max <
				ring->stats->common_stats.usage_cnt)
			ring->stats->common_stats.usage_max =
				ring->stats->common_stats.usage_cnt;

		status = VXGE_HW_OK;
		goto exit;
	}

	/* reset it. since we don't want to return
	 * garbage to the driver */
	*rxdh =	NULL;
	status = VXGE_HW_INF_NO_MORE_COMPLETED_DESCRIPTORS;
exit:
	return status;
}

/**
 * vxge_hw_ring_handle_tcode - Handle transfer code.
 * @ring: Handle to the ring object used for receive
 * @rxdh: Descriptor handle.
 * @t_code: One of the enumerated (and documented in the Titan user guide)
 * "transfer codes".
 *
 * Handle descriptor's transfer code. The latter comes with each completed
 * descriptor.
 *
 * Returns: one of the enum vxge_hw_status{} enumerated types.
 * VXGE_HW_OK			- for success.
 * VXGE_HW_ERR_CRITICAL         - when encounters critical error.
 */
enum vxge_hw_status vxge_hw_ring_handle_tcode(
	struct __vxge_hw_ring *ring, void *rxdh, u8 t_code)
{
	enum vxge_hw_status status = VXGE_HW_ERR_CRITICAL;

	/* If the t_code is not supported and if the
	 * t_code is other than 0x5 (unparseable packet
	 * such as unknown IPV6 header), Drop it !!!
	 */

	if (t_code ==  VXGE_HW_RING_T_CODE_OK ||
		t_code == VXGE_HW_RING_T_CODE_L3_PKT_ERR) {
		status = VXGE_HW_OK;
		goto exit;
	} else if (t_code > VXGE_HW_RING_T_CODE_MULTI_ERR) {
		status = VXGE_HW_ERR_INVALID_TCODE;
		goto exit;
	} else if (t_code == VXGE_HW_RING_T_CODE_BUF_SIZE_ERR)
		status = VXGE_HW_OK;

	ring->stats->rxd_t_code_err_cnt[t_code]++;
exit:
	return status;
}

/**
 * __vxge_hw_non_offload_db_post - Post non offload doorbell
 *
 * @fifo: fifohandle
 * @txdl_ptr: The starting location of the TxDL in host memory
 * @num_txds: The highest TxD in this TxDL (0 to 255 means 1 to 256)
 * @no_snoop: No snoop flags
 *
 * This function posts a non-offload doorbell to doorbell FIFO
 *
 */
static void __vxge_hw_non_offload_db_post(struct __vxge_hw_fifo *fifo,
	u64 txdl_ptr, u32 num_txds, u32 no_snoop)
{
	writeq(VXGE_HW_NODBW_TYPE(VXGE_HW_NODBW_TYPE_NODBW) |
		VXGE_HW_NODBW_LAST_TXD_NUMBER(num_txds) |
		VXGE_HW_NODBW_GET_NO_SNOOP(no_snoop),
		&fifo->nofl_db->control_0);

	mmiowb();

	writeq(txdl_ptr, &fifo->nofl_db->txdl_ptr);

	mmiowb();
}

/**
 * vxge_hw_fifo_free_txdl_count_get - returns the number of txdls available in
 * the fifo
 * @fifoh: Handle to the fifo object used for non offload send
 */
u32 vxge_hw_fifo_free_txdl_count_get(struct __vxge_hw_fifo *fifoh)
{
	return vxge_hw_channel_dtr_count(&fifoh->channel);
}

/**
 * vxge_hw_fifo_txdl_reserve - Reserve fifo descriptor.
 * @fifoh: Handle to the fifo object used for non offload send
 * @txdlh: Reserved descriptor. On success HW fills this "out" parameter
 *        with a valid handle.
 * @txdl_priv: Buffer to return the pointer to per txdl space
 *
 * Reserve a single TxDL (that is, fifo descriptor)
 * for the subsequent filling-in by driver)
 * and posting on the corresponding channel (@channelh)
 * via vxge_hw_fifo_txdl_post().
 *
 * Note: it is the responsibility of driver to reserve multiple descriptors
 * for lengthy (e.g., LSO) transmit operation. A single fifo descriptor
 * carries up to configured number (fifo.max_frags) of contiguous buffers.
 *
 * Returns: VXGE_HW_OK - success;
 * VXGE_HW_INF_OUT_OF_DESCRIPTORS - Currently no descriptors available
 *
 */
enum vxge_hw_status vxge_hw_fifo_txdl_reserve(
	struct __vxge_hw_fifo *fifo,
	void **txdlh, void **txdl_priv)
{
	enum vxge_hw_status status;
	int i;

	status = vxge_hw_channel_dtr_alloc(&fifo->channel, txdlh);

	if (status == VXGE_HW_OK) {
		struct vxge_hw_fifo_txd *txdp =
			(struct vxge_hw_fifo_txd *)*txdlh;
		struct __vxge_hw_fifo_txdl_priv *priv;

		priv = __vxge_hw_fifo_txdl_priv(fifo, txdp);

		/* reset the TxDL's private */
		priv->frags = 0;
		priv->alloc_frags = fifo->config->max_frags;
		priv->next_txdl_priv = NULL;

		*txdl_priv = (void *)(size_t)txdp->host_control;

		for (i = 0; i < fifo->config->max_frags; i++) {
			txdp = ((struct vxge_hw_fifo_txd *)*txdlh) + i;
			txdp->control_0 = txdp->control_1 = 0;
		}
	}

	return status;
}

/**
 * vxge_hw_fifo_txdl_buffer_set - Set transmit buffer pointer in the
 * descriptor.
 * @fifo: Handle to the fifo object used for non offload send
 * @txdlh: Descriptor handle.
 * @frag_idx: Index of the data buffer in the caller's scatter-gather list
 *            (of buffers).
 * @dma_pointer: DMA address of the data buffer referenced by @frag_idx.
 * @size: Size of the data buffer (in bytes).
 *
 * This API is part of the preparation of the transmit descriptor for posting
 * (via vxge_hw_fifo_txdl_post()). The related "preparation" APIs include
 * vxge_hw_fifo_txdl_mss_set() and vxge_hw_fifo_txdl_cksum_set_bits().
 * All three APIs fill in the fields of the fifo descriptor,
 * in accordance with the Titan specification.
 *
 */
void vxge_hw_fifo_txdl_buffer_set(struct __vxge_hw_fifo *fifo,
				  void *txdlh, u32 frag_idx,
				  dma_addr_t dma_pointer, u32 size)
{
	struct __vxge_hw_fifo_txdl_priv *txdl_priv;
	struct vxge_hw_fifo_txd *txdp, *txdp_last;
	struct __vxge_hw_channel *channel;

	channel = &fifo->channel;

	txdl_priv = __vxge_hw_fifo_txdl_priv(fifo, txdlh);
	txdp = (struct vxge_hw_fifo_txd *)txdlh  +  txdl_priv->frags;

	if (frag_idx != 0)
		txdp->control_0 = txdp->control_1 = 0;
	else {
		txdp->control_0 |= VXGE_HW_FIFO_TXD_GATHER_CODE(
			VXGE_HW_FIFO_TXD_GATHER_CODE_FIRST);
		txdp->control_1 |= fifo->interrupt_type;
		txdp->control_1 |= VXGE_HW_FIFO_TXD_INT_NUMBER(
			fifo->tx_intr_num);
		if (txdl_priv->frags) {
			txdp_last = (struct vxge_hw_fifo_txd *)txdlh  +
			(txdl_priv->frags - 1);
			txdp_last->control_0 |= VXGE_HW_FIFO_TXD_GATHER_CODE(
				VXGE_HW_FIFO_TXD_GATHER_CODE_LAST);
		}
	}

	vxge_assert(frag_idx < txdl_priv->alloc_frags);

	txdp->buffer_pointer = (u64)dma_pointer;
	txdp->control_0 |= VXGE_HW_FIFO_TXD_BUFFER_SIZE(size);
	fifo->stats->total_buffers++;
	txdl_priv->frags++;
}

/**
 * vxge_hw_fifo_txdl_post - Post descriptor on the fifo channel.
 * @fifo: Handle to the fifo object used for non offload send
 * @txdlh: Descriptor obtained via vxge_hw_fifo_txdl_reserve()
 * @tagged: Is the frame tagged
 *
 * Post descriptor on the 'fifo' type channel for transmission.
 * Prior to posting the descriptor should be filled in accordance with
 * Host/Titan interface specification for a given service (LL, etc.).
 *
 */
void vxge_hw_fifo_txdl_post(struct __vxge_hw_fifo *fifo, void *txdlh)
{
	struct __vxge_hw_fifo_txdl_priv *txdl_priv;
	struct vxge_hw_fifo_txd *txdp_last;
	struct vxge_hw_fifo_txd *txdp_first;
	struct __vxge_hw_channel *channel;
	u64 list_ptr;

	channel = &fifo->channel;

	txdl_priv = __vxge_hw_fifo_txdl_priv(fifo, txdlh);
	txdp_first = (struct vxge_hw_fifo_txd *)txdlh;

	txdp_last = (struct vxge_hw_fifo_txd *)txdlh  +  (txdl_priv->frags - 1);
	txdp_last->control_0 |=
	      VXGE_HW_FIFO_TXD_GATHER_CODE(VXGE_HW_FIFO_TXD_GATHER_CODE_LAST);

	list_ptr = (u64)txdl_priv->dma_addr;

	txdp_first->control_1 |= VXGE_HW_FIFO_TXD_NO_BW_LIMIT;
	list_ptr |= 0x1;

	txdp_first->control_0 |= VXGE_HW_FIFO_TXD_LIST_OWN_ADAPTER;

	vxge_hw_channel_dtr_post(&fifo->channel, txdlh);

#ifdef CONFIG_NOT_COHERENT_CACHE
        flush_dcache_range((unsigned long)txdp_first,
                        (unsigned long)((struct vxge_hw_fifo_txd *)txdp_first
                                + txdl_priv->frags));
#endif

	__vxge_hw_non_offload_db_post(fifo,
		list_ptr,
		txdl_priv->frags - 1,
		fifo->no_snoop_bits);

	fifo->stats->total_posts++;
	fifo->stats->common_stats.usage_cnt++;
	if (fifo->stats->common_stats.usage_max <
		fifo->stats->common_stats.usage_cnt)
		fifo->stats->common_stats.usage_max =
			fifo->stats->common_stats.usage_cnt;
}

/**
 * vxge_hw_fifo_txdl_next_completed - Retrieve next completed descriptor.
 * @fifo: Handle to the fifo object used for non offload send
 * @txdlh: Descriptor handle. Returned by HW.
 * @t_code: Transfer code, as per Titan User Guide,
 *          Transmit Descriptor Format.
 *          Returned by HW.
 *
 * Retrieve the _next_ completed descriptor.
 * HW uses channel callback (*vxge_hw_channel_callback_f) to notifiy
 * driver of new completed descriptors. After that
 * the driver can use vxge_hw_fifo_txdl_next_completed to retrieve the rest
 * completions (the very first completion is passed by HW via
 * vxge_hw_channel_callback_f).
 *
 * Implementation-wise, the driver is free to call
 * vxge_hw_fifo_txdl_next_completed either immediately from inside the
 * channel callback, or in a deferred fashion and separate (from HW)
 * context.
 *
 * Non-zero @t_code means failure to process the descriptor.
 * The failure could happen, for instance, when the link is
 * down, in which case Titan completes the descriptor because it
 * is not able to send the data out.
 *
 * For details please refer to Titan User Guide.
 *
 * Returns: VXGE_HW_OK - success.
 * VXGE_HW_INF_NO_MORE_COMPLETED_DESCRIPTORS - No completed descriptors
 * are currently available for processing.
 *
 */
enum vxge_hw_status vxge_hw_fifo_txdl_next_completed(
	struct __vxge_hw_fifo *fifo, void **txdlh,
	enum vxge_hw_fifo_tcode *t_code)
{
	struct __vxge_hw_channel *channel;
	struct vxge_hw_fifo_txd *txdp;
	enum vxge_hw_status status = VXGE_HW_OK;

	channel = &fifo->channel;

	vxge_hw_channel_dtr_try_complete(channel, txdlh);

	txdp = (struct vxge_hw_fifo_txd *)*txdlh;
	if (txdp == NULL) {
		status = VXGE_HW_INF_NO_MORE_COMPLETED_DESCRIPTORS;
		goto exit;
	}

	/* check whether host owns it */
	if (!(txdp->control_0 & VXGE_HW_FIFO_TXD_LIST_OWN_ADAPTER)) {

		vxge_assert(txdp->host_control != 0);

		vxge_hw_channel_dtr_complete(channel);

		*t_code = (u8)VXGE_HW_FIFO_TXD_T_CODE_GET(txdp->control_0);

		if (fifo->stats->common_stats.usage_cnt > 0)
			fifo->stats->common_stats.usage_cnt--;

		status = VXGE_HW_OK;
		goto exit;
	}

	/* no more completions */
	*txdlh = NULL;
	status = VXGE_HW_INF_NO_MORE_COMPLETED_DESCRIPTORS;
exit:
	return status;
}

/**
 * vxge_hw_fifo_handle_tcode - Handle transfer code.
 * @fifo: Handle to the fifo object used for non offload send
 * @txdlh: Descriptor handle.
 * @t_code: One of the enumerated (and documented in the Titan user guide)
 *          "transfer codes".
 *
 * Handle descriptor's transfer code. The latter comes with each completed
 * descriptor.
 *
 * Returns: one of the enum vxge_hw_status{} enumerated types.
 * VXGE_HW_OK - for success.
 * VXGE_HW_ERR_CRITICAL - when encounters critical error.
 */
enum vxge_hw_status vxge_hw_fifo_handle_tcode(struct __vxge_hw_fifo *fifo,
					      void *txdlh,
					      enum vxge_hw_fifo_tcode t_code)
{
	enum vxge_hw_status status = VXGE_HW_OK;

	if (((t_code & 0x7) < 0) || ((t_code & 0x7) > 0x4)) {
		status = VXGE_HW_ERR_INVALID_TCODE;
		goto exit;
	}

	fifo->stats->txd_t_code_err_cnt[t_code]++;
exit:
	return status;
}

/**
 * vxge_hw_fifo_txdl_free - Free descriptor.
 * @fifo: Handle to the fifo object used for non offload send
 * @txdlh: Descriptor handle.
 *
 * Free the reserved descriptor. This operation is "symmetrical" to
 * vxge_hw_fifo_txdl_reserve. The "free-ing" completes the descriptor's
 * lifecycle.
 *
 * After free-ing (see vxge_hw_fifo_txdl_free()) the descriptor again can
 * be:
 *
 * - reserved (vxge_hw_fifo_txdl_reserve);
 *
 * - posted (vxge_hw_fifo_txdl_post);
 *
 * - completed (vxge_hw_fifo_txdl_next_completed);
 *
 * - and recycled again (vxge_hw_fifo_txdl_free).
 *
 * For alternative state transitions and more details please refer to
 * the design doc.
 *
 */
void vxge_hw_fifo_txdl_free(struct __vxge_hw_fifo *fifo, void *txdlh)
{
	struct __vxge_hw_fifo_txdl_priv *txdl_priv;
	u32 max_frags;

	txdl_priv = __vxge_hw_fifo_txdl_priv(fifo,
			(struct vxge_hw_fifo_txd *)txdlh);

	max_frags = fifo->config->max_frags;

	vxge_hw_channel_dtr_free(&fifo->channel, txdlh);
}

/**
 * vxge_hw_vpath_vid_add_vpn - Add the vlan id entry for this vpath
 *               to vlan id table.
 * @vp: Vpath handle.
 * @vid: vlan id to be added for this vpath into the list
 *
 * Adds the given vlan id into the list for this  vpath.
 * see also: vxge_hw_vpath_vid_delete, vxge_hw_vpath_vid_get and
 * vxge_hw_vpath_vid_get_next
 *
 * XXX: Code to be merged after GA TODO
 */
enum vxge_hw_status
vxge_hw_vpath_vid_add_vpn(struct __vxge_hw_vpath_handle *vp, u64 vid,
				u32 vpn)
{
	enum vxge_hw_status status = VXGE_HW_OK;
	u64 data0 = 0x0, data1 = 0x0, steer_ctrl = 0x0;

	if (vp == NULL) {
		status = VXGE_HW_ERR_INVALID_HANDLE;
		goto exit;
	}

	data0 = VXGE_HW_RTS_ACCESS_STEER_DATA0_VLAN_ID(vid);

	data1 |= VXGE_HW_RTS_ACCESS_STEER_DATA1_PRIV_MODE_EN |
                VXGE_HW_RTS_ACCESS_STEER_DATA1_PRIV_MODE_VPN(vpn);

	status = vxge_hw_vpath_fw_api(vp->vpath->hldev, vp->vpath->vp_id,
			VXGE_HW_RTS_ACCESS_STEER_CTRL_ACTION_ADD_ENTRY,
			0, VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL_VID,
			&data0, &data1, &steer_ctrl);
exit:
	return status;
}

/**
 * vxge_hw_vpath_vid_delete_vpn - Delete the vlan id entry for this vpath
 *               to vlan id table.
 * @vp: Vpath handle.
 * @vid: vlan id to be deleted for this vpath into the list
 * @vpn: Vpath number
 *
 * Adds the given vlan id into the list for this  vpath.
 * see also: vxge_hw_vpath_vid_add_vpn, vxge_hw_vpath_vid_get_vpn and
 * vxge_hw_vpath_vid_get_next_vpn
 *
 * XXX: Code to be merged after GA TODO
 */
enum vxge_hw_status
vxge_hw_vpath_vid_delete_vpn(struct __vxge_hw_vpath_handle *vp, u64 vid,
					u32 vpn)
{
	enum vxge_hw_status status = VXGE_HW_OK;
	u64 data0 = 0x0, data1 = 0x0, steer_ctrl = 0x0;

	if (vp == NULL) {
		status = VXGE_HW_ERR_INVALID_HANDLE;
		goto exit;
	}

	data0 = VXGE_HW_RTS_ACCESS_STEER_DATA0_VLAN_ID(vid);

	data1 |= VXGE_HW_RTS_ACCESS_STEER_DATA1_PRIV_MODE_EN |
                VXGE_HW_RTS_ACCESS_STEER_DATA1_PRIV_MODE_VPN(vpn);

	status = vxge_hw_vpath_fw_api(vp->vpath->hldev, vp->vpath->vp_id,
			VXGE_HW_RTS_ACCESS_STEER_CTRL_ACTION_DELETE_ENTRY,
			0, VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL_VID,
			&data0, &data1, &steer_ctrl);
exit:
	return status;
}

/**
 * vxge_hw_vpath_vid_get_vpn - Get the first vid entry for this vpath
 *               from vlan id table.
 * @vp: Vpath handle.
 * @vid: Buffer to return vlan id
 * @vpn:
 *
 * Returns the first vlan id in the list for this vpath.
 * see also: vxge_hw_vpath_vid_get_next_vpn
 *
 */
enum vxge_hw_status
vxge_hw_vpath_vid_get_vpn(struct __vxge_hw_vpath_handle *vp, u64 *vid, u32 vpn)
{
	u64 data0 = 0ULL, data1 = 0ULL, steer_ctrl = 0ULL;
	enum vxge_hw_status status = VXGE_HW_OK;

	if (vp == NULL) {
		status = VXGE_HW_ERR_INVALID_HANDLE;
		goto exit;
	}

	data1 |= VXGE_HW_RTS_ACCESS_STEER_DATA1_PRIV_MODE_EN |  
			VXGE_HW_RTS_ACCESS_STEER_DATA1_PRIV_MODE_VPN(vpn);

	status = vxge_hw_vpath_fw_api(vp->vpath->hldev,
			vp->vpath->vp_id,
			VXGE_HW_RTS_ACCESS_STEER_CTRL_ACTION_LIST_FIRST_ENTRY,
			0, VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL_VID,
			&data0, &data1, &steer_ctrl);

	*vid = VXGE_HW_RTS_ACCESS_STEER_DATA0_GET_VLAN_ID(data0);

exit:
	return status;
}

/**
 * vxge_hw_vpath_vid_get_next_vpn - Get the next vid entry for this vpath
 *               from vlan id table.
 * @vp: Vpath handle.
 * @vid: Buffer to return vlan id
 *
 * Returns the next vlan id in the list for this vpath.
 * see also: vxge_hw_vpath_vid_get_vpn
 *
 */
enum vxge_hw_status
vxge_hw_vpath_vid_get_next_vpn(struct __vxge_hw_vpath_handle *vp, u64 *vid, u32 vpn)
{
	u64 data0 = 0ULL, data1 = 0ULL, steer_ctrl = 0ULL;
	enum vxge_hw_status status = VXGE_HW_OK;

	if (vp == NULL) {
		status = VXGE_HW_ERR_INVALID_HANDLE;
		goto exit;
	}

	data1 |= VXGE_HW_RTS_ACCESS_STEER_DATA1_PRIV_MODE_EN |  
			VXGE_HW_RTS_ACCESS_STEER_DATA1_PRIV_MODE_VPN(vpn);

	status = vxge_hw_vpath_fw_api(vp->vpath->hldev,
			vp->vpath->vp_id,
			VXGE_HW_RTS_ACCESS_STEER_CTRL_ACTION_LIST_NEXT_ENTRY,
			0, VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL_VID,
			&data0, &data1, &steer_ctrl);

	*vid = VXGE_HW_RTS_ACCESS_STEER_DATA0_GET_VLAN_ID(data0);

exit:
	return status;
}

/**
 * vxge_hw_vpath_mac_addr_del_vpn - Delete the mac address entry for this vpath
 *               to MAC address table.
 * @vp: Vpath handle.
 * @macaddr: MAC address to be added for this vpath into the list
 * @macaddr_mask: MAC address mask for macaddr
 * @vpn : Vpath number
 * Delete the given mac address and mac address mask for the vpath
 *
 */
enum vxge_hw_status
vxge_hw_vpath_mac_addr_del_vpn(
	struct __vxge_hw_vpath_handle *vp,
	u8 *macaddr,
	u8 *macaddr_mask,
	u32 vpn)
{
	u32 i;
	u64 data1 = 0ULL;
	u64 data2 = 0ULL, steer_ctrl = 0ULL;
	enum vxge_hw_status status = VXGE_HW_OK;

	if (vp == NULL) {
		status = VXGE_HW_ERR_INVALID_HANDLE;
		goto exit;
	}

	for (i = 0; i < ETH_ALEN; i++) {
		data1 <<= 8;
		data1 |= (u8)macaddr[i];

		data2 <<= 8;
		data2 |= (u8)macaddr_mask[i];
	}

	data1 = VXGE_HW_RTS_ACCESS_STEER_DATA0_DA_MAC_ADDR(data1);

	data2 = VXGE_HW_RTS_ACCESS_STEER_DATA1_DA_MAC_ADDR_MASK(data2);
	data2 |= VXGE_HW_RTS_ACCESS_STEER_DATA1_PRIV_MODE_EN |
                VXGE_HW_RTS_ACCESS_STEER_DATA1_PRIV_MODE_VPN(vpn);

	status = vxge_hw_vpath_fw_api(vp->vpath->hldev, vp->vpath->vp_id,
			VXGE_HW_RTS_ACCESS_STEER_CTRL_ACTION_DELETE_ENTRY,
			0, VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL_DA,
			&data1, &data2, &steer_ctrl);

exit:
	return status;
}

/**
 * vxge_hw_vpath_mac_addr_add_vpn - Add the mac address entry for this vpath
 *               to MAC address table.
 * @vp: Vpath handle.
 * @macaddr: MAC address to be added for this vpath into the list
 * @macaddr_mask: MAC address mask for macaddr
 * @duplicate_mode: Duplicate MAC address add mode. Please see
 *             enum vxge_hw_vpath_mac_addr_add_mode{}
 * @vpn: Vpath number
 *
 * Adds the given mac address and mac address mask into the list for this
 * vpath. This is to be used by the privilege driver
 * see also: vxge_hw_vpath_mac_addr_delete_vpn, vxge_hw_vpath_mac_addr_get_vpn and
 * vxge_hw_vpath_mac_addr_get_next_vpn
 *
 */
enum vxge_hw_status
vxge_hw_vpath_mac_addr_add_vpn(
	struct __vxge_hw_vpath_handle *vp,
	u8 *macaddr,
	u8 *macaddr_mask,
	enum vxge_hw_vpath_mac_addr_add_mode duplicate_mode,
	u32 vpn, unsigned int send_to_nw)
{
	u32 i;
	u64 data1 = 0ULL;
	u64 data2 = 0ULL, steer_ctrl = 0ULL;
	enum vxge_hw_status status = VXGE_HW_OK;

	if (vp == NULL) {
		status = VXGE_HW_ERR_INVALID_HANDLE;
		goto exit;
	}

	for (i = 0; i < ETH_ALEN; i++) {
		data1 <<= 8;
		data1 |= (u8)macaddr[i];

		data2 <<= 8;
		data2 |= (u8)macaddr_mask[i];
	}

	switch (duplicate_mode) {
	case VXGE_HW_VPATH_MAC_ADDR_ADD_DUPLICATE:
		i = 0;
		break;
	case VXGE_HW_VPATH_MAC_ADDR_DISCARD_DUPLICATE:
		i = 1;
		break;
	case VXGE_HW_VPATH_MAC_ADDR_REPLACE_DUPLICATE:
		i = 2;
		break;
	default:
		i = 0;
		break;
	}

	data1 = VXGE_HW_RTS_ACCESS_STEER_DATA0_DA_MAC_ADDR(data1);
	if (send_to_nw)
		data1 |= VXGE_HW_RTS_ACCESS_STEER_DATA0_SEND_TO_NW;

	data2 = VXGE_HW_RTS_ACCESS_STEER_DATA1_DA_MAC_ADDR_MASK(data2) |
                        VXGE_HW_RTS_ACCESS_STEER_DATA1_DA_MAC_ADDR_MODE(i);
	data2 |= VXGE_HW_RTS_ACCESS_STEER_DATA1_PRIV_MODE_EN |
                VXGE_HW_RTS_ACCESS_STEER_DATA1_PRIV_MODE_VPN(vpn);

	status = vxge_hw_vpath_fw_api(vp->vpath->hldev, vp->vpath->vp_id,
			VXGE_HW_RTS_ACCESS_STEER_CTRL_ACTION_ADD_ENTRY,
			0, VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL_DA,
			&data1, &data2, &steer_ctrl);

exit:
	return status;
}
/**
 * vxge_hw_vpath_mac_addr_get_vpn - Get the first mac address entry
 *               from MAC address table.
 * @vp: Vpath handle: Privileged vpath only.
 * @macaddr: First MAC address entry for vpath specified in the list
 * @macaddr_mask: MAC address mask for macaddr
 * @vpn: Vpath number: vpath number for which the mac address has
 *        to be retrieved
 *
 * Returns the first mac address and mac address mask in the list for the
 * vpath.
 * see also: vxge_hw_vpath_mac_addr_get_next_vpn
 *
 */
enum vxge_hw_status
vxge_hw_vpath_mac_addr_get_vpn(
	struct __vxge_hw_vpath_handle *vp,
	u8 *macaddr,
	u8 *macaddr_mask,
	u32 vpn)
{
	u32 i;
	u64 data1 = 0ULL;
	u64 data2 = 0ULL;
	u64 steer_ctrl = 0ULL;
	enum vxge_hw_status status = VXGE_HW_OK;

	vxge_assert(vp != NULL);

	if (vp == NULL) {
		status = VXGE_HW_ERR_INVALID_HANDLE;
		goto exit;
	}

	data2 = VXGE_HW_RTS_ACCESS_STEER_DATA1_PRIV_MODE_EN |
                VXGE_HW_RTS_ACCESS_STEER_DATA1_PRIV_MODE_VPN(vpn);

	status = vxge_hw_vpath_fw_api(vp->vpath->hldev, vp->vpath->vp_id,
			VXGE_HW_RTS_ACCESS_STEER_CTRL_ACTION_LIST_FIRST_ENTRY,
			0, VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL_DA,
			&data1, &data2, &steer_ctrl);

	if (status != VXGE_HW_OK)
		goto exit;

	data1 = VXGE_HW_RTS_ACCESS_STEER_DATA0_GET_DA_MAC_ADDR(data1);

	data2 = VXGE_HW_RTS_ACCESS_STEER_DATA1_GET_DA_MAC_ADDR_MASK(data2);

	for (i = ETH_ALEN; i > 0; i--) {
		macaddr[i-1] = (u8)(data1 & 0xFF);
		data1 >>= 8;

		macaddr_mask[i-1] = (u8)(data2 & 0xFF);
		data2 >>= 8;
	}
exit:
	return status;
}

/**
 * vxge_hw_vpath_mac_addr_get_next_vpn - Get the next mac address entry
 *               from MAC address table.
 * @vp: Vpath handle: Privileged vpath
 * @macaddr: Next MAC address entry for this vpath in the list
 * @macaddr_mask: MAC address mask for macaddr
 * @vpn: Vpath number: vpath number for which the mac address has
 *        to be retrieved
 *
 * Returns the next mac address and mac address mask in the list for this
 * vpath.
 * see also: vxge_hw_vpath_mac_addr_get_vpn
 *
 */
enum vxge_hw_status
vxge_hw_vpath_mac_addr_get_next_vpn(
	struct __vxge_hw_vpath_handle *vp,
	u8 *macaddr,
	u8 *macaddr_mask,
	u32 vpn)
{
	u32 i;
	u64 data1 = 0ULL;
	u64 data2 = 0ULL;
	u64 steer_ctrl = 0ULL;
	enum vxge_hw_status status = VXGE_HW_OK;

	vxge_assert(vp != NULL);

	if (vp == NULL) {
		status = VXGE_HW_ERR_INVALID_HANDLE;
		goto exit;
	}

	data2 = VXGE_HW_RTS_ACCESS_STEER_DATA1_PRIV_MODE_EN |
                VXGE_HW_RTS_ACCESS_STEER_DATA1_PRIV_MODE_VPN(vpn);

	status = vxge_hw_vpath_fw_api(vp->vpath->hldev, vp->vpath->vp_id,
			VXGE_HW_RTS_ACCESS_STEER_CTRL_ACTION_LIST_NEXT_ENTRY,
			0, VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL_DA,
			&data1, &data2, &steer_ctrl);

	if (status != VXGE_HW_OK)
		goto exit;

	data1 = VXGE_HW_RTS_ACCESS_STEER_DATA0_GET_DA_MAC_ADDR(data1);

	data2 = VXGE_HW_RTS_ACCESS_STEER_DATA1_GET_DA_MAC_ADDR_MASK(data2);

	for (i = ETH_ALEN; i > 0; i--) {
		macaddr[i-1] = (u8)(data1 & 0xFF);
		data1 >>= 8;

		macaddr_mask[i-1] = (u8)(data2 & 0xFF);
		data2 >>= 8;
	}

exit:
	return status;
}

/**
 * vxge_hw_vpath_handle_vlan_tag_strip - Enable/Disable vlan tag stripping.
 * @vp_id: Vpath Id.
 * @rpa_strip_vlan_tag: Flag to indicate whether to strip or
 * not to strip the vlan tag
 */
void vxge_hw_vpath_handle_vlan_tag_strip(
			struct __vxge_hw_device *hldev,
			u64 vp_id,
			u32 rpa_strip_vlan_tag)
{
	u64 val64;
	struct vxge_hw_vpath_reg __iomem *vp_reg;
	struct __vxge_hw_virtualpath *vpath;

	vpath = &hldev->virtual_paths[vp_id];
	vp_reg = (struct vxge_hw_vpath_reg __iomem *)hldev->vpath_reg[vp_id];

	val64 = readq(&vp_reg->xmac_rpa_vcfg);
	if (rpa_strip_vlan_tag)
		val64 |= VXGE_HW_XMAC_RPA_VCFG_STRIP_VLAN_TAG;
	else
		val64 &= ~VXGE_HW_XMAC_RPA_VCFG_STRIP_VLAN_TAG;
	writeq(val64, &vp_reg->xmac_rpa_vcfg);

	if (vpath->vp_open == VXGE_HW_VP_OPEN)
		vpath->vp_config->rpa_strip_vlan_tag = rpa_strip_vlan_tag;

	return;
}

/**
 * vxge_hw_vpath_get_vlan_tag_strip - Enable/Disable vlan tag stripping.
 * @vp: Vpath handle.
 */
u32 vxge_hw_vpath_get_vlan_tag_strip(
			struct __vxge_hw_device *hldev,
			u64 vp_id)
{
	u64 val64;
	struct vxge_hw_vpath_reg __iomem *vp_reg;

	vp_reg = (struct vxge_hw_vpath_reg __iomem *)hldev->vpath_reg[vp_id];
	val64 = readq(&vp_reg->xmac_rpa_vcfg);

	return ((val64 & VXGE_HW_XMAC_RPA_VCFG_STRIP_VLAN_TAG) ? 1 : 0);
}

/**
 * vxge_hw_vpath_promisc_enable - Enable promiscuous mode.
 * @vp: Vpath handle.
 *
 * Enable promiscuous mode of Titan-e operation.
 *
 * See also: vxge_hw_vpath_promisc_disable().
 */
void vxge_hw_vpath_promisc_enable(
			struct __vxge_hw_vpath_handle *vp)
{
	u64 val64;
	struct __vxge_hw_virtualpath *vpath;

	vpath = vp->vpath;

	val64 = readq(&vpath->vp_reg->rxmac_vcfg0);

	if (!(val64 & VXGE_HW_RXMAC_VCFG0_UCAST_ALL_ADDR_EN)) {

		val64 |= VXGE_HW_RXMAC_VCFG0_UCAST_ALL_ADDR_EN |
			 VXGE_HW_RXMAC_VCFG0_MCAST_ALL_ADDR_EN |
			 VXGE_HW_RXMAC_VCFG0_ALL_VID_EN;

		writeq(val64, &vpath->vp_reg->rxmac_vcfg0);
	}

	return;
}

/**
 * vxge_hw_vpath_promisc_disable - Disable promiscuous mode.
 * @vp: Vpath handle.
 *
 * Disable promiscuous mode of Titan-e operation.
 *
 * See also: vxge_hw_vpath_promisc_enable().
 */
void vxge_hw_vpath_promisc_disable(
			struct __vxge_hw_vpath_handle *vp)
{
	u64 val64;
	struct __vxge_hw_virtualpath *vpath;

	vpath = vp->vpath;

	val64 = readq(&vpath->vp_reg->rxmac_vcfg0);

	if (val64 & VXGE_HW_RXMAC_VCFG0_UCAST_ALL_ADDR_EN) {

		val64 &= ~(VXGE_HW_RXMAC_VCFG0_UCAST_ALL_ADDR_EN |
			   VXGE_HW_RXMAC_VCFG0_MCAST_ALL_ADDR_EN |
			   VXGE_HW_RXMAC_VCFG0_ALL_VID_EN);

		writeq(val64, &vpath->vp_reg->rxmac_vcfg0);
	}

	return;
}

/*
 * vxge_hw_vpath_bcast_enable - Enable broadcast
 * @vp: Vpath handle.
 *
 * Enable receiving broadcasts.
 */
enum vxge_hw_status vxge_hw_vpath_bcast_enable(
			struct __vxge_hw_vpath_handle *vp)
{
	u64 val64;
	struct __vxge_hw_virtualpath *vpath;
	enum vxge_hw_status status = VXGE_HW_OK;

	if ((vp == NULL) || (vp->vpath->ringh == NULL)) {
		status = VXGE_HW_ERR_INVALID_HANDLE;
		goto exit;
	}

	vpath = vp->vpath;

	val64 = readq(&vpath->vp_reg->rxmac_vcfg0);

	if (!(val64 & VXGE_HW_RXMAC_VCFG0_BCAST_EN)) {
		val64 |= VXGE_HW_RXMAC_VCFG0_BCAST_EN;
		writeq(val64, &vpath->vp_reg->rxmac_vcfg0);
	}
exit:
	return status;
}

/**
 * vxge_hw_vpath_mcast_enable - Enable multicast addresses.
 * @vp: Vpath handle.
 *
 * Enable Titan-e multicast addresses.
 * Returns: VXGE_HW_OK on success.
 *
 */
enum vxge_hw_status vxge_hw_vpath_mcast_enable(
			struct __vxge_hw_vpath_handle *vp)
{
	u64 val64;
	struct __vxge_hw_virtualpath *vpath;
	enum vxge_hw_status status = VXGE_HW_OK;

	if ((vp == NULL) || (vp->vpath->ringh == NULL)) {
		status = VXGE_HW_ERR_INVALID_HANDLE;
		goto exit;
	}

	vpath = vp->vpath;

	val64 = readq(&vpath->vp_reg->rxmac_vcfg0);

	if (!(val64 & VXGE_HW_RXMAC_VCFG0_MCAST_ALL_ADDR_EN)) {
		val64 |= VXGE_HW_RXMAC_VCFG0_MCAST_ALL_ADDR_EN;
		writeq(val64, &vpath->vp_reg->rxmac_vcfg0);
	}
exit:
	return status;
}

/**
 * vxge_hw_vpath_mcast_disable - Disable  multicast addresses.
 * @vp: Vpath handle.
 *
 * Disable Titan-e multicast addresses.
 * Returns: VXGE_HW_OK - success.
 * VXGE_HW_ERR_INVALID_HANDLE - Invalid handle
 *
 */
enum vxge_hw_status
vxge_hw_vpath_mcast_disable(struct __vxge_hw_vpath_handle *vp)
{
	u64 val64;
	struct __vxge_hw_virtualpath *vpath;
	enum vxge_hw_status status = VXGE_HW_OK;

	if ((vp == NULL) || (vp->vpath->ringh == NULL)) {
		status = VXGE_HW_ERR_INVALID_HANDLE;
		goto exit;
	}

	vpath = vp->vpath;

	val64 = readq(&vpath->vp_reg->rxmac_vcfg0);

	if (val64 & VXGE_HW_RXMAC_VCFG0_MCAST_ALL_ADDR_EN) {
		val64 &= ~VXGE_HW_RXMAC_VCFG0_MCAST_ALL_ADDR_EN;
		writeq(val64, &vpath->vp_reg->rxmac_vcfg0);
	}
exit:
	return status;
}

/**
 * vxge_hw_vpath_all_vid_enable - Enable all Vlan Ids.
 * @vp: Vpath handle.
 *
 * Enable all vlan ids.
 * Returns: VXGE_HAL_OK on success.
 *
 */
enum vxge_hw_status
vxge_hw_vpath_all_vid_enable(struct __vxge_hw_vpath_handle *vp)
{	u64 val64;
	struct __vxge_hw_virtualpath *vpath;
	enum vxge_hw_status status = VXGE_HW_OK;

	if ((vp == NULL) || (vp->vpath->ringh == NULL)) {
		status = VXGE_HW_ERR_INVALID_HANDLE;
		goto exit;
	}

	vpath = vp->vpath;

	val64 = readq(&vpath->vp_reg->rxmac_vcfg0);
	if (!(val64 & VXGE_HW_RXMAC_VCFG0_ALL_VID_EN)) {
		val64 |= VXGE_HW_RXMAC_VCFG0_ALL_VID_EN;
		writeq(val64, &vpath->vp_reg->rxmac_vcfg0);
	}
exit:
	return status;
}

/*
 * __vxge_hw_vpath_alarm_process - Process Alarms.
 * @vpath: Virtual Path.
 * @skip_alarms: Do not clear the alarms
 *
 * Process vpath alarms.
 *
 */
enum vxge_hw_status __vxge_hw_vpath_alarm_process(
			struct __vxge_hw_virtualpath *vpath,
			u32 skip_alarms)
{
	u64 val64;
	u64 alarm_status;
	u64 pic_status;
	struct vxge_hw_msg_data msg;
	struct __vxge_hw_device *hldev = NULL;
	enum vxge_hw_event alarm_event = VXGE_HW_EVENT_UNKNOWN;
	u64 mask64;
	struct vxge_hw_vpath_stats_sw_info *sw_stats;
	struct vxge_hw_vpath_reg __iomem *vp_reg;

	if (vpath == NULL)
		goto out2;

	hldev = vpath->hldev;
	vp_reg = vpath->vp_reg;
	alarm_status = readq(&vp_reg->vpath_general_int_status);

	if (alarm_status == VXGE_HW_ALL_FOXES) {
		alarm_event = max((enum vxge_hw_event)VXGE_HW_EVENT_SLOT_FREEZE,
			alarm_event);
		goto out;
	}

	sw_stats = vpath->sw_stats;

	if (alarm_status & ~(
		VXGE_HW_VPATH_GENERAL_INT_STATUS_PIC_INT |
		VXGE_HW_VPATH_GENERAL_INT_STATUS_PCI_INT |
		VXGE_HW_VPATH_GENERAL_INT_STATUS_WRDMA_INT |
		VXGE_HW_VPATH_GENERAL_INT_STATUS_XMAC_INT)) {
		sw_stats->error_stats.unknown_alarms++;

		alarm_event = max((enum vxge_hw_event)VXGE_HW_EVENT_UNKNOWN,
			alarm_event);
		goto out;
	}

	if (alarm_status & VXGE_HW_VPATH_GENERAL_INT_STATUS_XMAC_INT) {

		val64 = readq(&vp_reg->xgmac_vp_int_status);

		if (val64 &
		VXGE_HW_XGMAC_VP_INT_STATUS_ASIC_NTWK_VP_ERR_ASIC_NTWK_VP_INT) {

			val64 = readq(&vp_reg->asic_ntwk_vp_err_reg);

			if (((val64 &
				VXGE_HW_ASIC_NW_VP_ERR_REG_XMACJ_STN_FLT) &&
			    (!(val64 &
				VXGE_HW_ASIC_NW_VP_ERR_REG_XMACJ_STN_OK))) ||
			    ((val64 &
				VXGE_HW_ASIC_NW_VP_ERR_REG_XMACJ_STN_FLT_OCCURR)
				&& (!(val64 &
				VXGE_HW_ASIC_NW_VP_ERR_REG_XMACJ_STN_OK_OCCURR)
			))) {
				sw_stats->error_stats.network_sustained_fault++;

				writeq(
				VXGE_HW_ASIC_NW_VP_ERR_REG_XMACJ_STN_FLT,
					&vp_reg->asic_ntwk_vp_err_mask);

				__vxge_hw_device_handle_link_down_ind(hldev);
				alarm_event = max(
				(enum vxge_hw_event)VXGE_HW_EVENT_LINK_DOWN,
				alarm_event);
			}

			if (((val64 &
				VXGE_HW_ASIC_NW_VP_ERR_REG_XMACJ_STN_OK) &&
			    (!(val64 &
				VXGE_HW_ASIC_NW_VP_ERR_REG_XMACJ_STN_FLT))) ||
			    ((val64 &
				VXGE_HW_ASIC_NW_VP_ERR_REG_XMACJ_STN_OK_OCCURR)
				&& (!(val64 &
				VXGE_HW_ASIC_NW_VP_ERR_REG_XMACJ_STN_FLT_OCCURR)
			))) {

				sw_stats->error_stats.network_sustained_ok++;

				writeq(
				VXGE_HW_ASIC_NW_VP_ERR_REG_XMACJ_STN_OK,
					&vp_reg->asic_ntwk_vp_err_mask);

				__vxge_hw_device_handle_link_up_ind(hldev);
				alarm_event = max(
					(enum vxge_hw_event)
					VXGE_HW_EVENT_LINK_UP,
					alarm_event);
			}

			writeq(VXGE_HW_INTR_MASK_ALL,
				&vp_reg->asic_ntwk_vp_err_reg);

			alarm_event = max(
				(enum vxge_hw_event)VXGE_HW_EVENT_ALARM_CLEARED,
				alarm_event);

			if (skip_alarms)
				return VXGE_HW_OK;
		}
	}

	if (alarm_status & VXGE_HW_VPATH_GENERAL_INT_STATUS_PIC_INT) {

		pic_status = readq(&vp_reg->vpath_ppif_int_status);

		if (pic_status &
		    VXGE_HW_VPATH_PPIF_INT_STATUS_GENERAL_ERRORS_GENERAL_INT) {

			val64 = readq(&vp_reg->general_errors_reg);
			mask64 = readq(&vp_reg->general_errors_mask);

			if ((val64 &
				VXGE_HW_GENERAL_ERRORS_REG_INI_SERR_DET) &
				~mask64) {
				sw_stats->error_stats.ini_serr_det++;

				alarm_event = max(
					(enum vxge_hw_event)VXGE_HW_EVENT_SERR,
					alarm_event);
			}

			if ((val64 &
			    VXGE_HW_GENERAL_ERRORS_REG_DBLGEN_FIFO0_OVRFLOW) &
				~mask64) {
				sw_stats->error_stats.dblgen_fifo0_overflow++;

				alarm_event = max(
					(enum vxge_hw_event)
					VXGE_HW_EVENT_FIFO_ERR,
					alarm_event);
			}

			if ((val64 &
			    VXGE_HW_GENERAL_ERRORS_REG_STATSB_PIF_CHAIN_ERR) &
				~mask64)
				sw_stats->error_stats.statsb_pif_chain_error++;

			if ((val64 &
			   VXGE_HW_GENERAL_ERRORS_REG_STATSB_DROP_TIMEOUT_REQ) &
				~mask64)
				sw_stats->error_stats.statsb_drop_timeout++;

			if ((val64 &
				VXGE_HW_GENERAL_ERRORS_REG_TGT_ILLEGAL_ACCESS) &
				~mask64)
				sw_stats->error_stats.target_illegal_access++;

			if (!skip_alarms) {
				writeq(VXGE_HW_INTR_MASK_ALL,
					&vp_reg->general_errors_reg);
				alarm_event = max(
					(enum vxge_hw_event)
					VXGE_HW_EVENT_ALARM_CLEARED,
					alarm_event);
			}
		}

		if (pic_status &
		    VXGE_HW_VPATH_PPIF_INT_STATUS_KDFCCTL_ERRORS_KDFCCTL_INT) {

			val64 = readq(&vp_reg->kdfcctl_errors_reg);
			mask64 = readq(&vp_reg->kdfcctl_errors_mask);

			if ((val64 &
			    VXGE_HW_KDFCCTL_ERRORS_REG_KDFCCTL_FIFO0_OVRWR) &
				~mask64) {
				sw_stats->error_stats.kdfcctl_fifo0_overwrite++;

				alarm_event = max(
					(enum vxge_hw_event)
					VXGE_HW_EVENT_FIFO_ERR,
					alarm_event);
			}

			if ((val64 &
			    VXGE_HW_KDFCCTL_ERRORS_REG_KDFCCTL_FIFO0_POISON) &
				~mask64) {
				sw_stats->error_stats.kdfcctl_fifo0_poison++;

				alarm_event = max(
					(enum vxge_hw_event)
					VXGE_HW_EVENT_FIFO_ERR,
					alarm_event);
			}

			if ((val64 &
			    VXGE_HW_KDFCCTL_ERRORS_REG_KDFCCTL_FIFO0_DMA_ERR) &
				~mask64) {
				sw_stats->error_stats.kdfcctl_fifo0_dma_error++;

				alarm_event = max(
					(enum vxge_hw_event)
					VXGE_HW_EVENT_FIFO_ERR,
					alarm_event);
			}

			if (!skip_alarms) {
				writeq(VXGE_HW_INTR_MASK_ALL,
					&vp_reg->kdfcctl_errors_reg);
				alarm_event = max(
					(enum vxge_hw_event)
					VXGE_HW_EVENT_ALARM_CLEARED,
					alarm_event);
			}
		}

	}

	if (alarm_status & VXGE_HW_VPATH_GENERAL_INT_STATUS_WRDMA_INT) {

		val64 = readq(&vp_reg->wrdma_alarm_status);

		if (val64 & VXGE_HW_WRDMA_ALARM_STATUS_PRC_ALARM_PRC_INT) {

			val64 = readq(&vp_reg->prc_alarm_reg);
			mask64 = readq(&vp_reg->prc_alarm_mask);

			if ((val64 & VXGE_HW_PRC_ALARM_REG_PRC_RING_BUMP)&
				~mask64)
				sw_stats->error_stats.prc_ring_bumps++;

			if ((val64 & VXGE_HW_PRC_ALARM_REG_PRC_RXDCM_SC_ERR) &
				~mask64) {
				sw_stats->error_stats.prc_rxdcm_sc_err++;

				alarm_event = max(
					(enum vxge_hw_event)
					VXGE_HW_EVENT_VPATH_ERR,
					alarm_event);
			}

			if ((val64 & VXGE_HW_PRC_ALARM_REG_PRC_RXDCM_SC_ABORT)
				& ~mask64) {
				sw_stats->error_stats.prc_rxdcm_sc_abort++;

				alarm_event = max(
					(enum vxge_hw_event)
					VXGE_HW_EVENT_VPATH_ERR,
					alarm_event);
			}

			if ((val64 & VXGE_HW_PRC_ALARM_REG_PRC_QUANTA_SIZE_ERR)
				 & ~mask64) {
				sw_stats->error_stats.prc_quanta_size_err++;

				alarm_event = max(
					(enum vxge_hw_event)
					VXGE_HW_EVENT_VPATH_ERR,
					alarm_event);
			}

			if (!skip_alarms) {
				writeq(VXGE_HW_INTR_MASK_ALL,
					&vp_reg->prc_alarm_reg);
				alarm_event = max(
					(enum vxge_hw_event)
					VXGE_HW_EVENT_ALARM_CLEARED,
					alarm_event);
			}
		}
	}

	if (alarm_status & VXGE_HW_VPATH_GENERAL_INT_STATUS_PCI_INT) {
		val64 = readq(&vp_reg->vpath_pcipif_int_status);

			if (val64 &
				VXGE_HW_VP_PCIPIF_INT_STATUS_SRM_MSG_TO_VP_SRM_MSG_TO_VP_INT) {
			/* First clear the interrupt source */
			writeq(VXGE_HW_CLEAR_INTR_SOURCE_ALL,
					&vp_reg->srpcim_msg_to_vpath_reg);

			/* Get the type of the message that was received */
			vxge_hw_get_msg_data(vpath, &msg);

			vxge_hw_reenable_messages(vpath);

			if (msg.msg_type ==
					VXGE_HW_MSG_TYPE_SEND_SVID_TO_VF) {

				if (hldev->s_vid == msg.msg_data)
					goto no_update;
				hldev->s_vid = msg.msg_data;
				vpath->ringh->s_vid = msg.msg_data;
				vpath->fifoh->s_vid = msg.msg_data;

			} else if (msg.msg_type ==
				VXGE_HW_MSG_TYPE_SEND_CONFIG_GSO_TO_VF) {
				int vp_id = hldev->first_vp_id;
				/* update priority settings */
				if (hldev->config.vp_config[vp_id].vp_prio ==
								 msg.msg_data)
					goto no_update;
				hldev->config.vp_config[vp_id].vp_prio =
								msg.msg_data;
				vxge_config_gso(hldev->vdev, hldev->vdev->ndev);
			}
no_update:
			alarm_event = VXGE_HW_EVENT_ALARM_CLEARED;
		}
	}

out:
	hldev->stats.sw_dev_err_stats.vpath_alarms++;

out2:
	if ((alarm_event == VXGE_HW_EVENT_ALARM_CLEARED) ||
		(alarm_event == VXGE_HW_EVENT_UNKNOWN))
		return VXGE_HW_OK;

	__vxge_hw_device_handle_error(hldev, vpath->vp_id, alarm_event);

	if (alarm_event == VXGE_HW_EVENT_SERR)
		return VXGE_HW_ERR_CRITICAL;

	return (alarm_event == VXGE_HW_EVENT_SLOT_FREEZE) ?
		VXGE_HW_ERR_SLOT_FREEZE :
		(alarm_event == VXGE_HW_EVENT_FIFO_ERR) ? VXGE_HW_ERR_FIFO :
		VXGE_HW_ERR_VPATH;
}

/*
 * vxge_hw_vpath_alarm_process - Process Alarms.
 * @vpath: Virtual Path.
 * @skip_alarms: Do not clear the alarms
 *
 * Process vpath alarms.
 *
 */
enum vxge_hw_status vxge_hw_vpath_alarm_process(
			struct __vxge_hw_vpath_handle *vp,
			u32 skip_alarms)
{
	enum vxge_hw_status status = VXGE_HW_OK;

	if (vp == NULL) {
		status = VXGE_HW_ERR_INVALID_HANDLE;
		goto exit;
	}

	status = __vxge_hw_vpath_alarm_process(vp->vpath, skip_alarms);
exit:
	return status;
}

/**
 * vxge_hw_vpath_msix_set - Associate MSIX vectors with TIM interrupts and
 *                            alrms
 * @vp: Virtual Path handle.
 * @tim_msix_id: MSIX vectors associated with VXGE_HW_MAX_INTR_PER_VP number of
 *             interrupts(Can be repeated). If fifo or ring are not enabled
 *             the MSIX vector for that should be set to 0
 * @alarm_msix_id: MSIX vector for alarm.
 *
 * This API will associate a given MSIX vector numbers with the four TIM
 * interrupts and alarm interrupt.
 */
void
vxge_hw_vpath_msix_set(struct __vxge_hw_vpath_handle *vp, int *tim_msix_id,
		       int alarm_msix_id)
{
	u64 val64;
	struct __vxge_hw_virtualpath *vpath = vp->vpath;
	struct vxge_hw_vpath_reg __iomem *vp_reg = vpath->vp_reg;
	u32 vp_id = vp->vpath->vp_id;

	/* Write the internal msi-x vectors numbers */
	val64 = VXGE_HW_INTERRUPT_CFG0_GROUP0_MSIX_FOR_TXTI(
			(vp_id * 4) + tim_msix_id[0]) |
		VXGE_HW_INTERRUPT_CFG0_GROUP1_MSIX_FOR_TXTI(
			(vp_id * 4) + tim_msix_id[1]);

	writeq(val64, &vp_reg->interrupt_cfg0);

	writeq(VXGE_HW_INTERRUPT_CFG2_ALARM_MAP_TO_MSG(
			(vpath->hldev->first_vp_id * 4) + alarm_msix_id),
			&vp_reg->interrupt_cfg2);

	if (

		(vpath->hldev->config.intr_mode ==
					VXGE_HW_INTR_MODE_MSIX_ONE_SHOT)) {
		__vxge_hw_pio_mem_write32_upper((u32)vxge_bVALn(
				VXGE_HW_ONE_SHOT_VECT1_EN_ONE_SHOT_VECT1_EN,
				0, 32), &vp_reg->one_shot_vect1_en);
	}

	if (vpath->hldev->config.intr_mode ==
		VXGE_HW_INTR_MODE_MSIX_ONE_SHOT) {
		__vxge_hw_pio_mem_write32_upper((u32)vxge_bVALn(
				VXGE_HW_ONE_SHOT_VECT0_EN_ONE_SHOT_VECT0_EN,
				0, 32), &vp_reg->one_shot_vect0_en);

		__vxge_hw_pio_mem_write32_upper((u32)vxge_bVALn(
				VXGE_HW_ONE_SHOT_VECT2_EN_ONE_SHOT_VECT2_EN,
				0, 32), &vp_reg->one_shot_vect2_en);
	}

	return;
}

/**
 * vxge_hw_vpath_msix_mask - Mask MSIX Vector.
 * @vp: Virtual Path handle.
 * @msix_id:  MSIX ID
 *
 * The function masks the msix interrupt for the given msix_id
 *
 * Returns: 0,
 * Otherwise, VXGE_HW_ERR_WRONG_IRQ if the msix index is out of range
 * status.
 * See also:
 */
void
vxge_hw_vpath_msix_mask(struct __vxge_hw_vpath_handle *vp, int msix_id)
{
	struct __vxge_hw_device *hldev = vp->vpath->hldev;
	__vxge_hw_pio_mem_write32_upper(
		(u32) vxge_bVALn(vxge_mBIT(msix_id >> 2), 0, 32),
		&hldev->common_reg->set_msix_mask_vect[msix_id % 4]);

	return;
}

/**
 * vxge_hw_vpath_msix_clear - Clear MSIX Vector.
 * @vp: Virtual Path handle.
 * @msix_id:  MSI ID
 *
 * The function clears the msix interrupt for the given msix_id
 *
 * Returns: 0,
 * Otherwise, VXGE_HW_ERR_WRONG_IRQ if the msix index is out of range
 * status.
 * See also:
 */
void
vxge_hw_vpath_msix_clear(struct __vxge_hw_vpath_handle *vp, int msix_id)
{
	struct __vxge_hw_device *hldev = vp->vpath->hldev;

	if (

		(hldev->config.intr_mode ==
			VXGE_HW_INTR_MODE_MSIX_ONE_SHOT)) {
		__vxge_hw_pio_mem_write32_upper(
			(u32)vxge_bVALn(vxge_mBIT((msix_id >> 2)), 0, 32),
				&hldev->common_reg->
					clr_msix_one_shot_vec[msix_id%4]);
	} else {
		__vxge_hw_pio_mem_write32_upper(
			(u32)vxge_bVALn(vxge_mBIT((msix_id >> 2)), 0, 32),
				&hldev->common_reg->
					clear_msix_mask_vect[msix_id%4]);
	}

	return;
}

/**
 * vxge_hw_vpath_msix_unmask - Unmask the MSIX Vector.
 * @vp: Virtual Path handle.
 * @msix_id:  MSI ID
 *
 * The function unmasks the msix interrupt for the given msix_id
 *
 * Returns: 0,
 * Otherwise, VXGE_HW_ERR_WRONG_IRQ if the msix index is out of range
 * status.
 * See also:
 */
void
vxge_hw_vpath_msix_unmask(struct __vxge_hw_vpath_handle *vp, int msix_id)
{
	__vxge_hw_pio_mem_write32_upper(
		(u32)vxge_bVALn(vxge_mBIT(msix_id >> 2), 0, 32),
		&vp->vpath->hldev->common_reg->clear_msix_mask_vect[msix_id%4]);

	return;
}

/**
 * vxge_hw_vpath_msix_mask_all - Mask all MSIX vectors for the vpath.
 * @vp: Virtual Path handle.
 *
 * The function masks all msix interrupt for the given vpath
 *
 */
void
vxge_hw_vpath_msix_mask_all(struct __vxge_hw_vpath_handle *vp)
{
	__vxge_hw_pio_mem_write32_upper(
		(u32)vxge_bVALn(vxge_mBIT(vp->vpath->vp_id), 0, 32),
		&vp->vpath->hldev->common_reg->set_msix_mask_all_vect);

	return;
}

/**
 * vxge_hw_vpath_inta_mask_tx_rx - Mask Tx and Rx interrupts.
 * @vp: Virtual Path handle.
 *
 * Mask Tx and Rx vpath interrupts.
 *
 * See also: vxge_hw_vpath_inta_mask_tx_rx()
 */
void vxge_hw_vpath_inta_mask_tx_rx(struct __vxge_hw_vpath_handle *vp)
{
	u64	tim_int_mask0[4] = {[0 ...3] = 0};
	u32	tim_int_mask1[4] = {[0 ...3] = 0};
	u64	val64;
	struct __vxge_hw_device *hldev = vp->vpath->hldev;

	VXGE_HW_DEVICE_TIM_INT_MASK_SET(tim_int_mask0,
		tim_int_mask1, vp->vpath->vp_id);

	val64 = readq(&hldev->common_reg->tim_int_mask0);

	if ((tim_int_mask0[VXGE_HW_VPATH_INTR_TX] != 0) ||
		(tim_int_mask0[VXGE_HW_VPATH_INTR_RX] != 0)) {
		writeq((tim_int_mask0[VXGE_HW_VPATH_INTR_TX] |
			tim_int_mask0[VXGE_HW_VPATH_INTR_RX] | val64),
			&hldev->common_reg->tim_int_mask0);
	}

	val64 = readl(&hldev->common_reg->tim_int_mask1);

	if ((tim_int_mask1[VXGE_HW_VPATH_INTR_TX] != 0) ||
		(tim_int_mask1[VXGE_HW_VPATH_INTR_RX] != 0)) {
		__vxge_hw_pio_mem_write32_upper(
			(tim_int_mask1[VXGE_HW_VPATH_INTR_TX] |
			tim_int_mask1[VXGE_HW_VPATH_INTR_RX] | val64),
			&hldev->common_reg->tim_int_mask1);
	}

	return;
}

/**
 * vxge_hw_vpath_inta_unmask_tx_rx - Unmask Tx and Rx interrupts.
 * @vp: Virtual Path handle.
 *
 * Unmask Tx and Rx vpath interrupts.
 *
 * See also: vxge_hw_vpath_inta_mask_tx_rx()
 */
void vxge_hw_vpath_inta_unmask_tx_rx(struct __vxge_hw_vpath_handle *vp)
{
	u64	tim_int_mask0[4] = {[0 ...3] = 0};
	u32	tim_int_mask1[4] = {[0 ...3] = 0};
	u64	val64;
	struct __vxge_hw_device *hldev = vp->vpath->hldev;

	VXGE_HW_DEVICE_TIM_INT_MASK_SET(tim_int_mask0,
		tim_int_mask1, vp->vpath->vp_id);

	val64 = readq(&hldev->common_reg->tim_int_mask0);

	if ((tim_int_mask0[VXGE_HW_VPATH_INTR_TX] != 0) ||
	   (tim_int_mask0[VXGE_HW_VPATH_INTR_RX] != 0)) {
		writeq((~(tim_int_mask0[VXGE_HW_VPATH_INTR_TX] |
			tim_int_mask0[VXGE_HW_VPATH_INTR_RX])) & val64,
			&hldev->common_reg->tim_int_mask0);
	}

	if ((tim_int_mask1[VXGE_HW_VPATH_INTR_TX] != 0) ||
	   (tim_int_mask1[VXGE_HW_VPATH_INTR_RX] != 0)) {
		__vxge_hw_pio_mem_write32_upper(
			(~(tim_int_mask1[VXGE_HW_VPATH_INTR_TX] |
			  tim_int_mask1[VXGE_HW_VPATH_INTR_RX])) & val64,
			&hldev->common_reg->tim_int_mask1);
	}

	return;
}

/**
 * vxge_hw_vpath_doorbell_rx - Indicates to hw the qwords of receive
 * descriptors posted.
 * @ring: Handle to the ring object used for receive
 *
 * The function writes the number of qwords of rxds posted during replishment.
 * Since the function is called frequently, a flush is not required to post the
 * write transaction. At the very least, the previous write will be flushed
 * once the subsequent write is made.
 *
 * Returns: None.
 */
void vxge_hw_vpath_doorbell_rx(struct __vxge_hw_ring *ring, void *dtr_ptr)
{
	int rxds_qw_per_block = ring->rxds_per_block *
		VXGE_HW_RING_RXD_QWORDS_MODE_1;

	ring->doorbell_cnt += VXGE_HW_RING_RXD_QWORDS_MODE_1;

	ring->total_db_cnt += VXGE_HW_RING_RXD_QWORDS_MODE_1;

	if (ring->total_db_cnt >= rxds_qw_per_block) {
		/* For each block add 4 more qwords */
		ring->doorbell_cnt += VXGE_HW_RING_RXD_QWORDS_MODE_1;

		/* Reset total count */
		ring->total_db_cnt -= rxds_qw_per_block;
	}

	if (ring->doorbell_cnt >= ring->rxd_qword_limit) {
#ifdef CONFIG_NOT_COHERENT_CACHE
                flush_dcache_range((unsigned long)((u8*)dtr_ptr -
                                (ring->rxd_size * (ring->doorbell_cnt-1))),
                        (unsigned long)((u8 *)dtr_ptr + ring->rxd_size));
#endif
		mmiowb();
		writeq(VXGE_HW_PRC_RXD_DOORBELL_NEW_QW_CNT(
			ring->doorbell_cnt),
			&ring->vp_reg->prc_rxd_doorbell);
		ring->doorbell_cnt = 0;
	}
}

/**
 * vxge_hw_vpath_poll_rx - Poll Rx Virtual Path for completed
 * descriptors and process the same.
 * @ring: Handle to the ring object used for receive
 *
 * The function	polls the Rx for the completed	descriptors and	calls
 * the driver via supplied completion	callback.
 *
 * Returns: VXGE_HW_OK, if the polling is completed successful.
 * VXGE_HW_COMPLETIONS_REMAIN: There are still more completed
 * descriptors available which are yet to be processed.
 *
 * See also: vxge_hw_vpath_poll_rx()
 */
enum vxge_hw_status vxge_hw_vpath_poll_rx(struct __vxge_hw_ring *ring)
{
	u8 t_code;
	enum vxge_hw_status status = VXGE_HW_OK;
	void *first_rxdh;

	status = vxge_hw_ring_rxd_next_completed(ring, &first_rxdh, &t_code);
	if (status == VXGE_HW_OK)
		ring->callback(ring, first_rxdh,
			t_code, ring->channel.userdata);

	return status;
}

/**
 * vxge_hw_vpath_poll_tx - Poll Tx for completed descriptors and process
 * the same.
 * @fifo: Handle to the fifo object used for non offload send
 *
 * The function	polls the Tx for the completed	descriptors and	calls
 * the driver via supplied completion callback.
 *
 * Returns: VXGE_HW_OK, if the polling is completed successful.
 * VXGE_HW_COMPLETIONS_REMAIN: There are still more completed
 * descriptors available which are yet to be processed.
 *
 * See also: vxge_hw_vpath_poll_tx().
 */
enum vxge_hw_status vxge_hw_vpath_poll_tx(struct __vxge_hw_fifo *fifo,
					struct sk_buff ***skb_ptr, int nr_skb,
					int *more)
{
	enum vxge_hw_fifo_tcode t_code;
	void *first_txdlh;
	enum vxge_hw_status status = VXGE_HW_OK;
	struct __vxge_hw_channel *channel;

	channel = &fifo->channel;

	status = vxge_hw_fifo_txdl_next_completed(fifo,
				&first_txdlh, &t_code);
	if (status == VXGE_HW_OK)
		if (fifo->callback(fifo, first_txdlh, t_code,
			channel->userdata, skb_ptr, nr_skb, more) != VXGE_HW_OK)
			status = VXGE_HW_COMPLETIONS_REMAIN;

	return status;
}

static inline int vxge_os_is_my_packet(struct __vxge_hw_device *devh, u32 daddr)
{
	struct in_device *in_dev = NULL;
	struct in_ifaddr *ifa = NULL;
	struct net_device *dev = devh->ndev;

	in_dev = dev->ip_ptr;

	if (in_dev != NULL) {
		ifa = (struct in_ifaddr *) in_dev->ifa_list;
		while (ifa != NULL) {
			if (daddr == ifa->ifa_local)
				return 0;
			ifa = ifa->ifa_next;
		}
	}
	return 1;

}

/**
 * vxge_hw_vpath_set_lro_sg_size - Set the new s.
 * @vp: Vpath handle
 * @lro_sg_size: Max aggregatable pkts per session
 */
void vxge_hw_vpath_set_lro_sg_size(
			struct __vxge_hw_vpath_handle *vp, int lro_sg_size)
{
	struct __vxge_hw_virtualpath *vpath;
	struct __vxge_hw_ring *ring;

	vxge_assert(vp != NULL);
	vpath = vp->vpath;
	ring = vpath->ringh;
	if (ring) /* Did user configured this ring? */
		ring->config->sw_lro_sg_size = lro_sg_size;
}

/*
 * __hw_l4_pyld_length_get : Find the tcp seg len.
 * @tcp: tcp header.
 * @ip: ip header.
 *
 * Finds the tcp seg len.
 */
static inline u32
__hw_l4_pyld_length_get(struct tcphdr *tcp, struct iphdr *ip)
{
	u32 ret;
	ret = (ntohs(ip->tot_len) - (ip->ihl << 2) -
			(tcp->doff << 2));
	return ret;
}

enum vxge_hw_status
__vxge_hw_sw_lro_capable(
	struct __vxge_hw_ring *ring, u8 *buffer,
	struct iphdr **ip, struct tcphdr **tcp,
	struct vxge_hw_ring_rxd_info *ext_info)
{
	u8 ip_off, ip_length;
	u32 daddr;
	u16 vlan_id = 0;

	/* Check whether it is a TCP Packet Non TCP packets can not be LROed */
	if (!(ext_info->proto & VXGE_HW_FRAME_PROTO_TCP))
		return VXGE_HW_FAIL;

	if (!*ip) {

		if ((ext_info->frame == VXGE_HW_FRAME_TYPE_DIX) ||
			(ext_info->is_vlan ==  1)) {

			ip_off = ETH_HLEN;
			/* Get the Vlan ID of the frame */
			vlan_id = VXGE_HW_VLAN_VID_MASK & ext_info->vlan;
			/*
			 * If vlan stripping is disabled and the frame is VLAN
			 * tagged, shift the offset by the VLAN header size
			 * bytes.
			 */
			if ((ring->rpa_strip_vlan_tag ==
				VXGE_HW_VPATH_RPA_STRIP_VLAN_TAG_DISABLE) &&
				vlan_id)
				ip_off += VXGE_HW_HEADER_VLAN_SIZE;

		} else {
			/* LLC, SNAP etc are considered non-mergeable */
			return VXGE_HW_FAIL;
		}

		/* Grab ip headers */
		*ip = (struct iphdr *)((char *)buffer  +  ip_off);
	} /* !*ip */

	ip_length = (u8)(*ip)->ihl;
	ip_length = ip_length << 2;

	/* Grab the tcp header */
	*tcp = (struct tcphdr *)((char *)*ip  +  ip_length);

	if (ring->lro_enable == VXGE_HW_LRO_DONT_AGGR_FWD_PKTS) {
		daddr = (*ip)->daddr;
		/* Check if it is a broadcast or multicast ip */
		if (!vxge_os_in_multicast(daddr) &&
				(VXGE_OS_INADDR_BROADCAST != daddr)) {

			/*
			 * Does this packets destined for this interface?
			 */
			if (!vxge_os_is_my_packet(ring->channel.devh,
				daddr))
				return VXGE_HW_OK;

			/* Check if it is a vlan packet */
			if (ext_info->vlgrp && vlan_id) {
				struct net_device *vlan_dev = NULL;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 27))
				struct vlan_dev_info *vlan_info = NULL;
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 21))
				vlan_dev = vlan_group_get_device(
						ext_info->vlgrp, vlan_id);
#else
				vlan_dev =
					ext_info->vlgrp->vlan_devices[vlan_id];
#endif
				if (!vlan_dev)
					return VXGE_HW_FAIL;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 27))
				vlan_info = (struct vlan_dev_info *)
						netdev_priv(vlan_dev);
				if (!vlan_info)
					return VXGE_HW_FAIL;

				/* Is this a registered vlan? */
				if (vlan_info->real_dev == ext_info->dev)
#else
				if (vlan_dev_real_dev(vlan_dev) ==
							ext_info->dev)
#endif
					return VXGE_HW_OK;
			}

			return VXGE_HW_FAIL;

		}

	}
	return VXGE_HW_OK;

}

static int __hw_update_tcp_timestamp_slow(struct tcphdr *th,
	struct vxge_hw_sw_lro *lro, int save)
{
	unsigned char *ptr;
	int opt_cnt = 0;
	int length = ((th->doff << 2) - sizeof(struct tcphdr));

	ptr = (unsigned char *)(th  +  1);

	while (length > 0) {
		int opcode = *ptr++;
		int opsize;

		switch (opcode) {
		case VXGE_HW_TCPOPT_EOL:
			return 1;
		case VXGE_HW_TCPOPT_NOP:
			length--;
			continue;
		default:
			/* Not sure about this check, but not taking a chance */
			if ((opcode == VXGE_HW_TCPOPT_SACK_PERM) ||
				(opcode == VXGE_HW_TCPOPT_SACK))
				return 1;
			opsize = *ptr++;
			if (opsize < 2)
				return 1;
			/* don't parse partial options */
			if (opsize > length)
				return 1;
			if (++opt_cnt > 3)
				return 1;
			if (opcode == VXGE_HW_TCPOPT_TIMESTAMP) {
				if (opsize == VXGE_HW_TCPOLEN_TIMESTAMP) {
					if (save == VXGE_HW_TS_SAVE) {
						lro->cur_tsval =
							ntohl(
							*(__be32 *)ptr);
						lro->cur_tsecr =
							*(__be32 *)
							(ptr  +  4);
					} else if (save == VXGE_HW_TS_VERIFY) {
						/* Ensure timestamp value
						 * increases monotonically
						 */
						if (lro->cur_tsval >
							ntohl(
							*((__be32 *)ptr)))
							return -1;
						/* timestamp echo reply should
						 * be non-zero
						 */
						if (*((__be32 *)
							(ptr  +  4)) == 0)
							return -1;
					} else {
						__be32 *tmp_ptr =
							(__be32 *)
								(ptr  +  4);
						*tmp_ptr = lro->cur_tsecr;
					}
				return 0;
				}
			}
		ptr += opsize-2;
		length -= opsize;
		}
	}
	return 1;
}

static int __hw_update_tcp_timestamp(struct tcphdr *tcph,
	struct vxge_hw_sw_lro *lro, int save)
{
	if (tcph->doff == (sizeof(struct tcphdr) >> 2)) {
		return VXGE_HW_FAIL;

	} else if (tcph->doff == ((sizeof(struct tcphdr) >> 2)
			 + (VXGE_HW_TCPOLEN_TSTAMP_ALIGNED >> 2))) {

		__be32 *ptr = (__be32 *)(tcph  +  1);

		if (*ptr == htonl((VXGE_HW_TCPOPT_NOP << 24) |
					(VXGE_HW_TCPOPT_NOP << 16) |
					(VXGE_HW_TCPOPT_TIMESTAMP << 8) |
					VXGE_HW_TCPOLEN_TIMESTAMP)) {

			++ptr;
			if (save == VXGE_HW_TS_SAVE) {
				lro->cur_tsval = ntohl(
							*(__be32 *)ptr);
				lro->cur_tsecr = *(__be32 *)(ptr  +  1);
			} else if (save == VXGE_HW_TS_VERIFY) {
				/* Ensure timestamp value increases
					monotonically */
				if (lro->cur_tsval >
					ntohl(*((__be32 *)ptr)))
					return VXGE_HW_FAIL;

				/* timestamp echo reply should be non-zero */
				if (*((__be32 *)(ptr  +  1)) == 0)
					return VXGE_HW_FAIL;
			} else
				*(ptr  +  1) = lro->cur_tsecr;

		return VXGE_HW_OK;
		}
	}
	return __hw_update_tcp_timestamp_slow(tcph, lro, save);
}

static enum vxge_hw_status
__hw_lro_l3_l4_lro_capable(struct iphdr *ip,
	struct vxge_hw_ring_rxd_info *rxd_info,
	struct vxge_hw_sw_lro *lro,
	struct tcphdr *tcp, u32 tcp_pyld_len,
	u8 aggr_ack)
{
	u8 ip_length;
	if (!aggr_ack && !tcp_pyld_len) {
		/* Pure ACK */
		return VXGE_HW_FAIL;
	}

	 /* Ensure there are no IP options */
	ip_length = (u8)ip->ihl;
	ip_length = ip_length << 2;
	if (ip_length != sizeof(*ip))
		return VXGE_HW_FAIL;

	/* IP packet is not fragmented */
	if (rxd_info->proto & VXGE_HW_FRAME_PROTO_IP_FRAG)
		return VXGE_HW_FAIL;

	/* If we see CE codepoint in IP header, packet is not mergeable */
	if ((ip->tos & VXGE_HW_INET_ECN_MASK) == VXGE_HW_INET_ECN_CE)
		return VXGE_HW_FAIL;

	/* If we see ECE or CWR flags or CTRL flags in TCP header,
	 * packet is not mergeable */
	if (tcp->urg || tcp->psh || tcp->rst || tcp->syn ||
		tcp->fin || tcp->ece || tcp->cwr || !tcp->ack) {
		/*
		 * Currently recognize only the ack control word and
		 * any other control field being set would result in
		 * flushing the LRO session
		 */
		return VXGE_HW_FAIL;
	}

	if (lro)
		if (__hw_update_tcp_timestamp(tcp, lro, VXGE_HW_TS_VERIFY)
			== -1)
			return VXGE_HW_FAIL;

	return VXGE_HW_OK;
}
/*
 * __hw_append_lro: Appends new frame to existing LRO session.
 * @lro: lro pointer
 * @tcp: IN tcp	header, OUT tcp	payload.
 * @ip:	ip header.
 * @seg_len: tcp payload length.
 *
 * Appends new frame to existing LRO session.
 */
static inline enum vxge_hw_status
__hw_append_lro(struct vxge_hw_sw_lro *lro,
	struct tcphdr **tcp,
	struct iphdr *ip,
	u32 *tcp_seg_len)
{
	*tcp_seg_len = __hw_l4_pyld_length_get(*tcp, ip);
	lro->total_length += *tcp_seg_len;
	lro->frags_len += *tcp_seg_len;
	lro->tcp_next_seq_num += *tcp_seg_len;
	lro->window = (*tcp)->window;
	if (lro->saw_ts)
		__hw_update_tcp_timestamp((*tcp), lro, VXGE_HW_TS_SAVE);
	/*
	 * Update mbuf chain will be done in ll	driver.
	 * xge_hw_accumulate_large_rx on success of appending new frame to
	 * lro will return to ll driver	tcpdata	pointer, and tcp payload length.
	 * along with return code lro frame appended.
	 */
	lro->tcp_seq_num = (*tcp)->seq;
	lro->tcp_ack_num = (*tcp)->ack_seq;

	lro->sg_num++;
	*tcp = (struct tcphdr *)((char *)*tcp  + ((*tcp)->doff << 2));

	return VXGE_HW_OK;
}

void vxge_hw_update_L3L4_header(
	struct __vxge_hw_ring *ring,
	struct vxge_hw_sw_lro *lro)
{
	struct tcphdr *tcp = lro->tcph;
	struct iphdr *ip = lro->iph;
	u16 nchk;

	vxge_assert(ring != NULL);

	/* Update L3 Header */
	ip->tot_len = htons(lro->total_length);
	ip->check = 0;
	nchk = ip_fast_csum((u8 *)ip, ip->ihl);
	ip->check = nchk;

	/* Update L4 Header */
	tcp->ack_seq = lro->tcp_ack_num;
	tcp->window = lro->window;

	/* Update tsecr field if this session has timestamps enabled */
	if (lro->saw_ts)
		__hw_update_tcp_timestamp(tcp, lro, VXGE_HW_TS_UPDATE);

	ring->stats->lro_num_aggregations++;
	ring->stats->lro_sum_avg_pkts_aggregated += lro->sg_num;
}

/*
 * __hw_lro_check_for_session_match: Check if frame belongs to given lro.
 * @lro: LRO session
 * @tcp: tcp header.
 * @ip: ip header.
 *
 * Check if frame belongs to given lro.
 */
static inline enum vxge_hw_status
__hw_lro_check_for_session_match(struct vxge_hw_sw_lro *lro,
	struct tcphdr *tcp, struct iphdr *ip)
{
	if ((lro->iph->saddr != ip->saddr) ||
		(lro->iph->daddr != ip->daddr) ||
		(lro->tcph->source != tcp->source) ||
		(lro->tcph->dest != tcp->dest))
			return VXGE_HW_FAIL;

	return VXGE_HW_OK;
}

/*
 * __hw_lro_under_optimal_thresh: Finds whether combined session is optimal.
 * @ring: Handle to the ring object used for receive
 * @lro: lro pointer
 * @tcp: tcp header.
 * @ip:	ip header.
 *
 * Finds whether combined session is optimal.
 */
static inline enum vxge_hw_status
__hw_lro_under_optimal_thresh(struct __vxge_hw_ring *ring,
		struct vxge_hw_sw_lro *lro,
		struct tcphdr *tcp, struct iphdr *ip)
{
	if (!lro)
		return VXGE_HW_FAIL;

	if ((lro->total_length + __hw_l4_pyld_length_get(tcp, ip)) >
				ring->config->sw_lro_frm_len) {
		return VXGE_HW_FAIL;
	}

	if (lro->sg_num	== ring->config->sw_lro_sg_size)
		return VXGE_HW_FAIL;

	return VXGE_HW_OK;
}

/*
 * __hw_open_lro_session: Open a new LRO session.
 * @ring: Handle to the ring object used for receive
 * @buffer: Ethernet frame.
 * @tcp: tcp header.
 * @ip: ip header.
 * @lro: lro pointer
 * @tcp_seg_len: Length of tcp segment.
 *
 *  Opens a new LRO session.
 */
static inline  enum vxge_hw_status
__hw_open_lro_session(
	struct __vxge_hw_ring *ring, u8 *buffer,
	struct tcphdr *tcp,
	struct iphdr *ip,
	struct vxge_hw_sw_lro **lro,
	u32 tcp_seg_len)
{
	if (!list_empty(&ring->free_sw_lros)) {
		*lro = list_entry(ring->free_sw_lros.next,
				struct vxge_hw_sw_lro, lro_node);
		list_del(&(*lro)->lro_node);
		list_add(&(*lro)->lro_node, &ring->active_sw_lros);
	} else {
		*lro = NULL;
		return VXGE_HW_INF_SW_LRO_UNCAPABLE;
	}

	(*lro)->iph			= ip;
	(*lro)->tcph			= tcp;
	(*lro)->window			= tcp->window;
	(*lro)->tcp_next_seq_num	= tcp_seg_len  +
						ntohl(tcp->seq);
	(*lro)->tcp_seq_num		= tcp->seq;
	(*lro)->tcp_ack_num		= tcp->ack_seq;
	(*lro)->sg_num			= 1;
	(*lro)->total_length		= ntohs(ip->tot_len);
	(*lro)->frags_len		= 0;

	/*
	 * check if we saw TCP timestamp. Other consistency checks have
	 * already been done.
	 */
	if (!__hw_update_tcp_timestamp(tcp, *lro, VXGE_HW_TS_SAVE))
		(*lro)->saw_ts = 1;

	return VXGE_HW_OK;

}

/*
 * __hw_get_lro_session: Gets matching LRO session or creates one.
 * @ring: Handle to the ring object used for receive
 * @rxd_info: Descriptor info.
 * @eth_hdr:    Ethernet header.
 * @tcp: tcp header.
 * @ip: ip header.
 * @lro: lro pointer
 *
 * Gets matching LRO session or creates one.
 */
static inline  enum vxge_hw_status
__hw_get_lro_session(
	struct __vxge_hw_ring *ring,
	struct vxge_hw_ring_rxd_info *rxd_info,
	u8 *eth_hdr,
	struct tcphdr *tcp,
	struct iphdr *ip,
	struct vxge_hw_sw_lro **lro)
{
	struct vxge_hw_sw_lro *lro_desc;
	u32 tcp_seg_len;

	*lro = NULL;

	/*
	 * Search in the pool of LROs for the session that matches
	 * the incoming frame.
	 */
	list_for_each_entry(lro_desc, &ring->active_sw_lros, lro_node) {
		if (__hw_lro_check_for_session_match(lro_desc, tcp, ip) ==
								VXGE_HW_OK) {
				*lro = lro_desc;
				break;
		}
	}

	tcp_seg_len = __hw_l4_pyld_length_get(tcp, ip);
	if (*lro) {
		/*
		 * Matching LRO Session found
		 */
		if ((*lro)->tcp_next_seq_num != ntohl(tcp->seq)) {
			/* Out of Order Packets */
			ring->stats->lro_outof_sequence_pkts++;
			return VXGE_HW_INF_SW_LRO_FLUSH_BOTH;
		}
		if (__hw_lro_l3_l4_lro_capable(ip, rxd_info, *lro, tcp,
						tcp_seg_len,
						ring->aggr_ack))
			return VXGE_HW_INF_SW_LRO_FLUSH_BOTH;

		/*
		 * The frame is good, in-sequence, can be LRO-ed;
		 * take its (latest) ACK - unless it is a dupack.
		 * Note: to be exact need to check window size as well..
		 */
		if ((*lro)->tcp_ack_num == tcp->ack_seq &&
					(*lro)->tcp_seq_num == tcp->seq) {
			return VXGE_HW_INF_SW_LRO_FLUSH_BOTH;
		}

		return VXGE_HW_INF_SW_LRO_CONT;
	}

	/*********** New Session ***************/

	if (__hw_lro_l3_l4_lro_capable(ip, rxd_info, *lro, tcp,
					tcp_seg_len,
					ring->aggr_ack))
		return VXGE_HW_INF_SW_LRO_UNCAPABLE;

	if (__hw_open_lro_session(ring, eth_hdr, tcp, ip, lro, tcp_seg_len)
					!= VXGE_HW_OK)
		return VXGE_HW_INF_SW_LRO_UNCAPABLE;

	return VXGE_HW_INF_SW_LRO_BEGIN;
}

static void
vxge_hw_sw_lro_reset_node(struct vxge_hw_sw_lro *sw_lro)
{
	/* Need better way to reset */
	sw_lro->os_buf = NULL;
	sw_lro->iph = NULL;
	sw_lro->tcph = NULL;
	sw_lro->tcp_next_seq_num = 0;
	sw_lro->tcp_seq_num = 0;
	sw_lro->tcp_ack_num = 0;
	sw_lro->sg_num = 0;
	sw_lro->total_length = 0;
	sw_lro->frags_len = 0;
	sw_lro->cur_tsval = 0;
	sw_lro->cur_tsecr = 0;
	sw_lro->saw_ts = 0;
	sw_lro->window = 0;
	sw_lro->vlan_tag = 0;
}

/**
 * vxge_hw_sw_lro_session_close: Close LRO session
 * @ring: Handle to the ring object used for receive
 * @sw_lro: LRO Session. Please see struct vxge_hw_sw_lro{}
 *
 *  Closes the LRO session
 */
void
vxge_hw_sw_lro_session_close(
	struct __vxge_hw_ring *ring,
	struct vxge_hw_sw_lro *sw_lro)
{
	vxge_assert(ring != NULL);

	list_del(&sw_lro->lro_node);

	ring->active_sw_lro_count--;

	vxge_hw_sw_lro_reset_node(sw_lro);

	list_add(&sw_lro->lro_node, &ring->free_sw_lros);
	ring->free_sw_lro_count++;
}

/**
 * xge_hw_sw_lro_next_session_get: get the next LRO session
 * @ring: Handle to the ring object used for receive
 * @sw_lro: Current LRO Session. If zero, the function will return the
 *             first LRO session
 *
 *  Returns the next LRO session
 */
struct vxge_hw_sw_lro *
vxge_hw_sw_lro_next_session_get(
	struct __vxge_hw_ring *ring,
	struct vxge_hw_sw_lro *sw_lro)
{
	struct vxge_hw_sw_lro *next_lro = NULL;

	vxge_assert(ring != NULL);

	if (sw_lro == NULL) {
		if (!list_empty(&ring->active_sw_lros))
			next_lro = list_entry(ring->active_sw_lros.next,
				struct vxge_hw_sw_lro, lro_node);
	} else {
		if (!list_empty(&sw_lro->lro_node))
			next_lro = list_entry(sw_lro->lro_node.next,
				struct vxge_hw_sw_lro, lro_node);
	}

	if (next_lro != NULL) {
		next_lro->iph->tot_len = htons(
			next_lro->total_length);
		next_lro->iph->check = htons(0);
		next_lro->iph->check = ip_fast_csum(
			(u8 *)(next_lro->iph),
			next_lro->iph->ihl);
	}

	return next_lro;
}

/**
 * __vxge_hw_sw_lro_terminate - Terminate lro resources.
 * @ring: Handle to the ring object used for receive
 *
 *  Terminate lro resources.
 */
enum vxge_hw_status
__vxge_hw_sw_lro_terminate(struct __vxge_hw_ring *ring)
{
	struct vxge_hw_sw_lro *lro_desc, *lro_desc_next;

	vxge_assert(ring != NULL);

	if (ring->active_sw_lro_count > 0) {

		list_for_each_entry_safe(lro_desc, lro_desc_next,
				&ring->active_sw_lros, lro_node) {

			list_del(&lro_desc->lro_node);
			vfree(lro_desc);
			ring->active_sw_lro_count--;
		}
	}

	if (ring->free_sw_lro_count > 0) {

		list_for_each_entry_safe(lro_desc, lro_desc_next,
				&ring->free_sw_lros, lro_node) {
			list_del(&lro_desc->lro_node);
			vfree(lro_desc);
			ring->free_sw_lro_count--;
		}
	}

	return VXGE_HW_OK;
}

/*
 * __vxge_hw_sw_lro_init - Initiate lro resources.
 * @ring: Handle to the ring object used for receive
 *
 *  Initiate lro resources.
 */

enum vxge_hw_status
__vxge_hw_sw_lro_init(struct __vxge_hw_ring *ring)
{
	u32 i;
	struct vxge_hw_sw_lro *lro_session;

	vxge_assert(ring != NULL);

	INIT_LIST_HEAD(&ring->active_sw_lros);

	ring->active_sw_lro_count = 0;

	INIT_LIST_HEAD(&ring->free_sw_lros);

	ring->free_sw_lro_count = 0;

	for (i = 0; i < ring->config->sw_lro_sessions; i++) {
		lro_session = (struct vxge_hw_sw_lro *)\
				vmalloc(sizeof(struct vxge_hw_sw_lro));
		if (lro_session == NULL) {
			__vxge_hw_sw_lro_terminate(ring);

			return VXGE_HW_ERR_OUT_OF_MEMORY;
		}

		vxge_hw_sw_lro_reset_node(lro_session);
		lro_session->lro_node.next = NULL;
		lro_session->lro_node.prev = NULL;
		list_add(&lro_session->lro_node, &ring->free_sw_lros);
		ring->free_sw_lro_count++;
	}

	return VXGE_HW_OK;
}

/**
 * __vxge_hw_sw_lro_reset - Reset lro resources.
 * @ring: Handle to the ring object used for receive
 *
 *  Reset lro resources.
 */
enum vxge_hw_status
__vxge_hw_sw_lro_reset(struct __vxge_hw_ring *ring)
{
	struct vxge_hw_sw_lro *lro_desc;

	vxge_assert(ring != NULL);

	if (ring->active_sw_lro_count > 0) {

		list_for_each_entry(lro_desc, &ring->active_sw_lros, lro_node) {

			list_del(&lro_desc->lro_node);

			ring->active_sw_lro_count--;
			vxge_hw_sw_lro_reset_node(lro_desc);

			list_add(&lro_desc->lro_node, &ring->free_sw_lros);
			ring->free_sw_lro_count++;
		}
	}

	return VXGE_HW_OK;
}

/**
 * vxge_hw_sw_lro_rx_process: Process Rx Buffer
 * @ring: Handle to the ring object used for receive
 * @rxd_info: Please see struct vxge_hw_ring_rxd_info{}
 * @eth_hdr: Ethernet header (start of frame buffer)
 * @ip: Ip Header. Please see struct iphdr{}
 * @tcp: Buffer to return pointer to struct tcphdr{}
 * @sw_lro: Buffer to return pointer to struct vxge_hw_sw_lro{}
 *
 * Processes the rx buffer and either creates new lro session or
 * appends to the existing lro session
 */
enum vxge_hw_status
vxge_hw_sw_lro_rx_process(
	struct __vxge_hw_ring *ring,
	struct vxge_hw_ring_rxd_info *rxd_info,
	u8 *eth_hdr,
	u32 *seglen,
	struct vxge_hw_sw_lro **sw_lro)
{
	enum vxge_hw_status status;
	struct iphdr *ip = NULL;
	struct tcphdr *tcp = NULL;

	vxge_assert(ring != NULL);

	if (__vxge_hw_sw_lro_capable(ring, eth_hdr, &ip, &tcp, rxd_info) !=
			VXGE_HW_OK) {
		return VXGE_HW_INF_SW_LRO_UNCAPABLE;
	}

	/*
	 * This	function shall get matching LRO or else
	 * create one and return it
	 */
	status = __hw_get_lro_session(ring, rxd_info, eth_hdr,
			tcp, ip, sw_lro);

	if (status == VXGE_HW_INF_SW_LRO_CONT) {
		if (__hw_lro_under_optimal_thresh(ring, *sw_lro, tcp, ip)
						== VXGE_HW_OK) {
			(void) __hw_append_lro(*sw_lro, &tcp, ip, seglen);
			ring->stats->lro_clubbed_frms_cnt++;

			if ((*sw_lro)->sg_num >= ring->config->sw_lro_sg_size)
				status = VXGE_HW_INF_SW_LRO_FLUSH_SESSION;

		} else
			status = VXGE_HW_INF_SW_LRO_FLUSH_BOTH;
	}

	/*
	 * Since its time to flush,
	 * update ip header so that it can be sent up
	 */
	if (status == VXGE_HW_INF_SW_LRO_FLUSH_SESSION) {
		vxge_hw_update_L3L4_header(ring, *sw_lro);
		ring->stats->lro_flush_max_pkts++;
	} else if (status == VXGE_HW_INF_SW_LRO_FLUSH_BOTH) {
		vxge_hw_update_L3L4_header(ring, *sw_lro);
		ring->stats->lro_sending_both++;
	}

	if (*sw_lro) {
		if (rxd_info->is_vlan == 1)
			(*sw_lro)->vlan_tag = rxd_info->vlan;
		if ((*sw_lro)->sg_num > ring->stats->lro_max_pkts_aggr)
			ring->stats->lro_max_pkts_aggr = (*sw_lro)->sg_num;
	}

	return status;
}
