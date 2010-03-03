/* cnic_drv.h: Broadcom CNIC core network driver.
 *
 * Copyright (c) 2008 Broadcom Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 *
 */


#ifndef CNIC_DRV_H
#define CNIC_DRV_H

#if !defined(__iomem)
#define __iomem
#endif

struct kwqe;
struct kcqe;
struct kwqe_16;

#define MAX_CNIC_CTL_DATA	64
#define MAX_DRV_CTL_DATA	64

#define CNIC_CTL_STOP_CMD		1
#define CNIC_CTL_START_CMD		2
#define CNIC_CTL_COMPLETION_CMD		3

#define DRV_CTL_IO_WR_CMD		0x101
#define DRV_CTL_IO_RD_CMD		0x102
#define DRV_CTL_CTX_WR_CMD		0x103
#define DRV_CTL_CTXTBL_WR_CMD		0x104
#define DRV_CTL_COMPLETION_CMD		0x105

struct cnic_ctl_completion {
	u32	cid;
};

struct drv_ctl_completion {
	u32	comp_count;
};

struct cnic_ctl_info {
	int	cmd;
	union {
		struct cnic_ctl_completion comp;
		char bytes[MAX_CNIC_CTL_DATA];
	} data;
};

struct drv_ctl_io {
	u32		cid_addr;
	u32		offset;
	u32		data;
	dma_addr_t	dma_addr;
};

struct drv_ctl_info {
	int	cmd;
	union {
		struct drv_ctl_completion comp;
		struct drv_ctl_io io;
		char bytes[MAX_DRV_CTL_DATA];
	} data;
};

struct cnic_ops {
	struct module	*cnic_owner;
	/* Calls to these functions are protected by RCU.  When
	 * unregistering, we wait for any calls to complete before
	 * continuing.
	 */
	int		(*cnic_handler)(void *, void *);
	int		(*cnic_ctl)(void *, struct cnic_ctl_info *);
	unsigned long	reserved[2];
};

#define MAX_CNIC_VEC	8

struct cnic_irq {
	unsigned int	vector;
	void		*status_blk;
	u32		status_blk_num;
	u32		irq_flags;
#define CNIC_IRQ_FL_MSIX		0x00000001
};

struct cnic_eth_dev {
	struct module	*drv_owner;
	u32		drv_state;
#define CNIC_DRV_STATE_REGD		0x00000001
#define CNIC_DRV_STATE_USING_MSIX	0x00000002
	u32		chip_id;
	u32		max_kwqe_pending;
	struct pci_dev	*pdev;
	void __iomem	*io_base;

	u32		ctx_tbl_offset;
	u32		ctx_tbl_len;
	int		ctx_blk_size;
	u32		starting_cid;
	u32		max_iscsi_conn;
	u32		max_fcoe_conn;
	u32		max_rdma_conn;
	u32		reserved0[2];

	int		num_irq;
	struct cnic_irq	irq_arr[MAX_CNIC_VEC];
	int		(*drv_register_cnic)(struct net_device *,
					     struct cnic_ops *, void *);
	int		(*drv_unregister_cnic)(struct net_device *);
	int		(*drv_submit_kwqes_32)(struct net_device *,
					       struct kwqe *[], u32);
	int		(*drv_submit_kwqes_16)(struct net_device *,
					       struct kwqe_16 *[], u32);
	int		(*drv_ctl)(struct net_device *, struct drv_ctl_info *);
	unsigned long	reserved1[2];
};

#ifdef __VMKLNX__
extern struct cnic_eth_dev *bnx2_cnic_probe(struct net_device *);
#endif

#endif
