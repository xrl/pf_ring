/***********************************************************************
 * This software may be used and distributed according to the terms of
 * the GNU General Public License (GPL), incorporated herein by reference.
 * Drivers based on or derived from this code fall under the GPL and must
 * retain the authorship, copyright and license notice.  This file is not
 * a complete program and may only be used when the entire operating
 * system is licensed under the GPL.
 * See the file COPYING in this distribution for more information.
 ************************************************************************/
/*******************************************************************************
 * vxge-manage.h:
 * Linux PCIe Ethernet driver for Neterion 10GbE Server NIC
 * Copyright(c) 2002-2010 Exar Corp.
 ******************************************************************************/
#ifndef _VXGE_MANAGE_H
#define _VXGE_MANAGE_H

struct bw_flow_info {
	int tx;
	int rx;
	int priority;
};

enum vxge_hw_vpath_mac_addr_origin {
	VXGE_HW_VPATH_MAC_ADDR_ORIGIN_NOT_LEARNED	= 0,
	VXGE_HW_VPATH_MAC_ADDR_ORIGIN_LEARNED		= 1
};

struct macInfo {
	unsigned char macaddr[6];
	unsigned char macmask[6];
	unsigned int vpath_no;
	enum vxge_hw_vpath_mac_addr_origin origin;
	unsigned int send_to_nw;
};

typedef struct macList {
	unsigned int vpath_no;
	unsigned int macaddr_no;
	struct macInfo mac_info[128];
} macList_t;

typedef struct tracebufInfo {
#define TRACE_BUFFER_SIZE 16384
	unsigned char * buffer;
	unsigned int buf_size;
	unsigned int read_length;
} tracebufInfo_t;

typedef struct ioctlInfo {
	int cmd;
	unsigned long long value;
	unsigned long long txbytes;
	unsigned long long rxbytes;
	unsigned long long debug_level;
	unsigned long long debug_mask;
	unsigned long reg_offset;
	unsigned long reg_index;
	unsigned long reg_type;
	unsigned char *buffer;
	unsigned char *buffer1;
	unsigned char *buffer2;
	unsigned char *buffer3;
	unsigned char *buffer4;
	unsigned char *buffer5;
	unsigned char *buffer6;
	int size;

} ioctlInfo_t;

struct privioctlInfo {
	/*
	 * Indicates which operation the driver needs to perform, one of
	 * i)  get_vf_stats
	 * ii) get_mrpcim_stats etc
	 * This is updated by the user-app
	 */
	int op;

	int direction; /* 0: get, 1: set */

	/* Virtual function id. This is updated by the user app */
	int vfid;

	/*
	 * Indicates the size of the buffer populated.
	 * This is updated by user app before making the ioctl call.
	 */
	int size;

	/* Return code for the ioctl */
	int ret;

	/*
	 * The pre-formatted buffer returned by the driver. This is allocated
	 * by the user app and passed to the driver where it is populated
	 */
	u64 buffer;
}__attribute((packed));
typedef struct privioctlInfo vxge_priv_ioctlInfo_t;

#define VXGE_CASE_GOTO_BREAK(x)	\
	if (menu_interface) 	\
		goto x;		\
	else			\
		break;		

#define VXGE_FALSE_INPUT_GOTO(x)					\
        if (!(vxge_is_numeric(opt))) {					\
        printf("\n### ERROR : Invalid Input Format ###\n");		\
        goto x;								\
}

#define VXGE_FALSE_VFID_GOTO(x)					\
	if( vfid < 0 || vfid > 7) {				\
		printf("\n### ERROR: Invalid VF ID ###\n");	\
		goto x;						\
	}

#define VXGE_GET_DEVICE_STATS 		1000
#define VXGE_GET_NUM_DEV_MACADDR	1001
#define VXGE_GET_DEV_MACADDR		1002
#define VXGE_GET_NUM_VF_MACADDR		1003
#define VXGE_GET_VF_MACADDR		1004
#define VXGE_GET_NUM_VF_VLANS		1005
#define VXGE_GET_VF_VLANS		1006
#define VXGE_GET_NUM_DEV_VLANS		1007
#define VXGE_GET_DEV_VLANS		1008
#define VXGE_GET_VPATH_STATS		1009
#define VXGE_ADD_VF_MACADDR		1010
#define VXGE_DEL_VF_MACADDR		1011
#define VXGE_ADD_VF_VLANID		1012
#define VXGE_DEL_VF_VLANID		1013
#define VXGE_VF_RX_BW			1014
#define VXGE_VF_TX_BW			1015
#define VXGE_VF_PRIORITY		1016
#define VXGE_VF_PRIV_FN_NUM		1017
#define VXGE_VF_VLAN_TAG_STRIP		1018
#define VXGE_PF_FLOW_CTRL		1019
#define VXGE_PROMISC_ON_PORT0		1020
#define VXGE_PROMISC_ON_PORT1		1021
#define VXGE_MIRROR_VEB_ON_PORT0	1022
#define VXGE_MIRROR_VEB_ON_PORT1	1023
#define VXGE_VEPA_MODE			1024
#define VXGE_ADD_VF_SVLANID		1025
#define VXGE_DEL_VF_SVLANID		1026

#endif /* _VXGE_MANAGE_H */
