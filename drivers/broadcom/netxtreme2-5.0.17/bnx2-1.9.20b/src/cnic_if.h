/* cnic_if.h: Broadcom CNIC core network driver.
 *
 * Copyright (c) 2006 - 2009 Broadcom Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 *
 * Written by: John(Zongxi) Chen  (zongxic@broadcom.com)
 */


#ifndef CNIC_IF_H
#define CNIC_IF_H

#define CNIC_MODULE_VERSION	"1.9.3"
#define CNIC_MODULE_RELDATE	"July 9, 2009"

#define CNIC_ULP_RDMA		0
#define CNIC_ULP_ISCSI		1
#define CNIC_ULP_L4		2
#define MAX_CNIC_ULP_TYPE_EXT	2
#define MAX_CNIC_ULP_TYPE	3

struct kwqe {
	u32 kwqe_op_flag;

#define KWQE_OPCODE_MASK	0x00ff0000
#define KWQE_OPCODE_SHIFT	16
#define KWQE_OPCODE(x)		((x & KWQE_OPCODE_MASK) >> KWQE_OPCODE_SHIFT)

	u32 kwqe_info0;
	u32 kwqe_info1;
	u32 kwqe_info2;
	u32 kwqe_info3;
	u32 kwqe_info4;
	u32 kwqe_info5;
	u32 kwqe_info6;
};

struct kwqe_16 {
	u32 kwqe_info0;
	u32 kwqe_info1;
	u32 kwqe_info2;
	u32 kwqe_info3;
};

struct kcqe {
	u32 kcqe_info0;
	u32 kcqe_info1;
	u32 kcqe_info2;
	u32 kcqe_info3;
	u32 kcqe_info4;
	u32 kcqe_info5;
	u32 kcqe_info6;
	u32 kcqe_op_flag;
		#define KCQE_RAMROD_COMPLETION		(0x1<<27) /* Everest */
		#define KCQE_FLAGS_LAYER_MASK		(0x7<<28)
		#define KCQE_FLAGS_LAYER_MASK_MISC	(0<<28)
		#define KCQE_FLAGS_LAYER_MASK_L2	(2<<28)
		#define KCQE_FLAGS_LAYER_MASK_L3	(3<<28)
		#define KCQE_FLAGS_LAYER_MASK_L4	(4<<28)
		#define KCQE_FLAGS_LAYER_MASK_L5_RDMA	(5<<28)
		#define KCQE_FLAGS_LAYER_MASK_L5_ISCSI	(6<<28)
		#define KCQE_FLAGS_NEXT 		(1<<31)
		#define KCQE_FLAGS_OPCODE_MASK		(0xff<<16)
		#define KCQE_FLAGS_OPCODE_SHIFT		(16)
		#define KCQE_OPCODE(op)			\
		(((op) & KCQE_FLAGS_OPCODE_MASK) >> KCQE_FLAGS_OPCODE_SHIFT)
};

struct cnic_sockaddr {
	union {
		struct sockaddr_in	v4;
		struct sockaddr_in6	v6;
	} local;
	union {
		struct sockaddr_in	v4;
		struct sockaddr_in6	v6;
	} remote;
};

struct cnic_sock {
	struct cnic_dev *dev;
	void	*context;
	u32	src_ip[4];
	u32	dst_ip[4];
	u16	src_port;
	u16	dst_port;
	u16	vlan_id;
	unsigned char old_ha[6];
#ifdef __VMKLNX__
	unsigned char ha[6];
#endif
	u16	pmtu;
	struct dst_entry *dst;
	u32	cid;
	u32	l5_cid;
	u32	pg_cid;
	int	ulp_type;

	u32	ka_timeout;
	u32	ka_interval;
	u8	ka_max_probe_count;
	u8	tos;
	u8	ttl;
	u8	snd_seq_scale;
	u32	rcv_buf;
	u32	snd_buf;
	u32	seed;

	unsigned long	tcp_flags;
#define SK_TCP_NO_DELAY_ACK	0x1
#define SK_TCP_KEEP_ALIVE	0x2
#define SK_TCP_NAGLE		0x4
#define SK_TCP_TIMESTAMP	0x8
#define SK_TCP_SACK		0x10
#define SK_TCP_SEG_SCALING	0x20

	unsigned long	flags;
#define SK_F_INUSE		0
#define SK_F_OFFLD_COMPLETE	1
#define SK_F_OFFLD_SCHED	2
#define SK_F_PG_OFFLD_COMPLETE	3
#define SK_F_CONNECT_START	4
#define SK_F_IPV6		5
#define SK_F_NDISC_WAITING	6
#define SK_F_CLOSING		7

	atomic_t ref_count;
	u32 state;
	struct kwqe kwqe1;
	struct kwqe kwqe2;
	struct kwqe kwqe3;
};

struct cnic_dev {
	struct net_device	*netdev;
	struct pci_dev		*pcidev;
	void __iomem		*regview;
	struct list_head	list;

	int (*register_device)(struct cnic_dev *dev, int ulp_type,
			       void *ulp_ctx);
	int (*unregister_device)(struct cnic_dev *dev, int ulp_type);
	int (*submit_kwqes)(struct cnic_dev *dev, struct kwqe *wqes[],
				u32 num_wqes);

	int (*cm_create)(struct cnic_dev *, int, u32, u32, struct cnic_sock **,
			 void *);
	int (*cm_destroy)(struct cnic_sock *);
	int (*cm_connect)(struct cnic_sock *, struct cnic_sockaddr *);
	int (*cm_abort)(struct cnic_sock *);
	int (*cm_close)(struct cnic_sock *);
#ifdef __VMKLNX__
	struct cnic_dev *(*cm_select_dev)(vmk_IscsiNetHandle iscsiNetHandle, 
					  struct sockaddr_in *, int ulp_type);
#else
	struct cnic_dev *(*cm_select_dev)(struct sockaddr_in *, int ulp_type);
#endif
	unsigned long flags;
#define CNIC_F_IF_UP		0
#define CNIC_F_CNIC_UP		1
#define CNIC_F_IF_GOING_DOWN	2
#define CNIC_F_BNX2_CLASS	3
#define CNIC_F_BNX2X_CLASS	4
	atomic_t ref_count;
	int use_count;

	int max_iscsi_conn;
	int max_fcoe_conn;
	int max_rdma_conn;

	void *cnic_priv;
};

#define CNIC_WR(dev, off, val)		writel(val, dev->regview + off)
#define CNIC_WR16(dev, off, val)	writew(val, dev->regview + off)
#define CNIC_WR8(dev, off, val)		writeb(val, dev->regview + off)
#define CNIC_RD(dev, off)		readl(dev->regview + off)
#define CNIC_RD16(dev, off)		readw(dev->regview + off)

struct cnic_ulp_ops {
	/* Calls to these functions are protected by RCU.  When
	 * unregistering, we wait for any calls to complete before
	 * continuing.
	 */

	void (*cnic_init)(struct cnic_dev *dev);
	void (*cnic_exit)(struct cnic_dev *dev);
	void (*cnic_start)(void *ulp_ctx);
	void (*cnic_stop)(void *ulp_ctx);
	void (*indicate_kcqes)(void *ulp_ctx, struct kcqe *cqes[],
				u32 num_cqes);
	void (*indicate_netevent)(void *ulp_ctx, unsigned long event);
	void (*indicate_inetevent)(void *ulp_ctx, unsigned long event);
	void (*cm_connect_complete)(struct cnic_sock *);
	void (*cm_close_complete)(struct cnic_sock *);
	void (*cm_abort_complete)(struct cnic_sock *);
	void (*cm_remote_close)(struct cnic_sock *);
	void (*cm_remote_abort)(struct cnic_sock *);
	struct module *owner;
};

extern int cnic_register_driver(int ulp_type, struct cnic_ulp_ops *ulp_ops);

extern int cnic_unregister_driver(int ulp_type);

#endif
