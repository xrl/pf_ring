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
 * vxge-dev.h : definitions and prototypes for vxge-dev.c
 */

#ifndef __VXGE_DEV_H
#define __VXGE_DEV_H

#include <string.h>
#include "vxge-data.h"

#define VXGE_PROC_BASE_ENTRY    "/proc/net/vxge/base"
#define VXGE_PROC_DEV_ENTRY     "/proc/net/vxge/dev_table"

#define VXGE_BASE_MAGIC_OBJ     VXGEBDNAME 
#define VXGE_TABLE_MAGIC_OBJ    VXGEDEINDEX 

#define VXGE_MAX_CHAR_PER_LINE  512

#if 0
static inline void __get_parser_format(struct vxge_data *obj,
		char *format, const char *prefix) 
{
	int type = obj->vp->type;

	strcpy(format, prefix);
	switch (type) {
	case ASN_OCTET_STR:
		strcat(format, "%s");
		break;
	case ASN_INTEGER: 
		strcat(format, "%d");
		break;
	case ASN_COUNTER:
		strcat(format, "%ld");
		break;
	}
}
#endif

int vxge_get_driver_status(void);
int vxge_dev_table_size(void);
void vxgedev_get_base_object(int magic, struct vxge_data *obj, 
		char *string, long *long_ret);
void vxgedev_get_table_object(int magic, struct vxge_data *obj, 
		char *string, long *long_ret);
int vxgedev_trap_snapshot(struct vxge_trap_info *trap);

#endif /* __VXGE_DEV_H */
