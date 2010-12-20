/**
 * NET-SNMP agent for Neterion Inc's X3100 Series 
 * 10Gbps network Adapters.
 * 
 * Copyright(c) 2002-2010 Exar Inc.
 *
 * This software may be used and distributed according to the terms of
 * the GNU General Public License (GPL), incorporated herein by reference.
 * Software based on or derived from this code fall under the GPL and must
 * retain the authorship, copyright and license notice.  This file is not
 * a complete program and may only be used when the entire operating
 * system is licensed under the GPL.
 * See the file COPYING in this distribution for more information.
 *
 * vxge-data.h : definitions and prototypes for vxge-data.c
 */ 

#ifndef __VXGE_DATA_H
#define __VXGE_DATA_H

#include "vxge-agent.h"

/* vxge generic mib objects */
#define VXGE_VENDOR       "Neterion.Inc"
#define VXGE_PRODUCT      "X3100 Series 10Gb Ethernet Adapter"
#define VXGE_HOST_LEN     255
#define VXGE_DEFAULT_HOST "Unknown"
#define VXGE_MIB_VERSION  "2"

#define vxge_log(fmt...)  do { \
			snmp_log(LOG_ERR, "vxge:: %s:%d  ", \
					__func__, __LINE__); \
			snmp_log(LOG_ERR, fmt); \
		} while (0);

/* structure that holds mib object detailes */
struct vxge_data {
	
	int             table_index;
	struct variable *vp;
	oid             *name;
	size_t          *name_len;
	size_t          *var_len;
	unsigned char   *data;
	WriteMethod     **write_method;
};

#define VXGE_TRAP_POLL_INTERVAL 10
#define VXGE_TRAP_IFACE_ADDED   1
#define VXGE_TRAP_IFACE_REMOVED 2
#define VXGE_TRAP_LINK_UP       3
#define VXGE_TRAP_LINK_DOWN     4

struct vxge_iface {
	char name[32];
	long index;
	int link_state;
};

struct vxge_trap_info {
	/* indicate whether trap enabled*/
	long notify;
	/* variable to store the alard registration id */
	unsigned int alarm_id;
	/* number of interfaces stored in the below dev array */
	int dev_count;
	int link_up_count;
#define VXGE_MAX_DEV 32
	struct vxge_iface dev[VXGE_MAX_DEV];
};

unsigned char *
vxge_get_scalar(struct vxge_data *obj);

unsigned char *
vxge_get_table_entry(struct vxge_data *obj);

void vxge_trap_manage(struct vxge_trap_info *trap, long enable);

#endif /* __VXGE_DATA_H */

