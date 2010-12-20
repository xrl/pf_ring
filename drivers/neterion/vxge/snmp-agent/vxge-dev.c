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
 * vxge-dev.c : It talks to vxge driver and process on requested 
 *              mib object.
 */ 

#include "vxge-agent.h"
#include "vxge-dev.h"

/*
 * vxge_get_driver_status();
 *    function checks whether vxge driver with MIB 
 *    support is loaded or not. It will return 0,
 *    if loaded driver is compiled without VXGE_SNMP.
 * returns:
 *    1 if vxge with MIB support loaded
 *    0 otherwise.
 */ 
int vxge_get_driver_status(void)
{
	FILE *f;

	if (!(f = fopen(VXGE_PROC_BASE_ENTRY, "r"))) 
		return 0;
	fclose(f);
	return 1;
}

/* 
 * vxge_dev_table_size():
 *      Find the number of rows in the dev_table 
 *      proc entry. It equals the number of vxge
 *      interfaces configured.
 * Returns:
 *      row size of the dev_table,
 *      -1 on error
 */ 
int vxge_dev_table_size(void)
{
	FILE *f;
	int dev_count = 0;
	char line[VXGE_MAX_CHAR_PER_LINE];

	if (!(f = fopen(VXGE_PROC_DEV_ENTRY, "r"))) {
		vxge_log("%s open error\n", 
				VXGE_PROC_DEV_ENTRY);
		return -1;
	}

	while (fgets(line, sizeof(line), f))
		dev_count++;
	
	fclose(f);
	/* skip the header */
	return (dev_count - 1);
}

/*
 * vxgedev_get_base_object():
 *      It reads the base driver object from the proc file
 *      /proc/net/vxge/base. The format of the file is 
 *      assumed to be "param name: param value".
 * @magic : index of the mib object
 * @obj   : reference to the corresponding mib object struct
 * @string: static data storage for the string objects
 * @long_ret: static data storage for the integer type objects
 *
 * Returns: void
 */ 
void vxgedev_get_base_object(int magic, struct vxge_data *obj, 
		char *string, long *long_ret)
{
	FILE *f;
	int  line_offset = 0;
	int  line_count  = 0;
	char line[VXGE_MAX_CHAR_PER_LINE];

	if (!(f = fopen(VXGE_PROC_BASE_ENTRY, "r"))) {
		vxge_log("%s open error\n", 
				VXGE_PROC_BASE_ENTRY);
		goto err;
	}
	/* calculate the line number of the object in the file */
	line_offset = magic - VXGE_BASE_MAGIC_OBJ;

	while (fgets(line, sizeof(line), f) 
			&& line_count < line_offset)
		line_count++;
	
	if (line_count != line_offset) {
		/* should not be here */
		vxge_log("object#%d not found in %s\n", 
				magic, VXGE_PROC_BASE_ENTRY);
		goto err1;
	}

	if (obj->vp->type == ASN_OCTET_STR) {
		/* 
		 * base proc entry should be in the format,
		 * "object name: value" for easiness of parsing 
		 */
		if (1 != sscanf(line, "%*[a-zA-Z0-9_ -]: %[A-Za-z0-9:._ -]", 
				string)) {
			vxge_log("parser error for object #%d in %s\n", 
					magic, VXGE_PROC_BASE_ENTRY);
			goto err1;
		}
		*obj->var_len = strlen(string);
		obj->data     = (unsigned char*)string;
	} else {
		/* Assumes type will be intger or counter */
		if (1 != sscanf(line, "%*[a-zA-Z0-9_ -]: %ld", long_ret)) {
			vxge_log("parser error for object #%d in %s\n", 
					magic, VXGE_PROC_BASE_ENTRY);
			goto err1;
		}
		obj->data = (unsigned char *)long_ret;
	}
	fclose(f);
	return;
err1:
	fclose(f);
err:
	obj->data = NULL;
}

/*
 * vxgedev_get_table_object():
 *      It reads the device table object from the proc file
 *      /proc/net/vxge/dev_table. Column number of the object
 *      in the row should be matched to magic index number.
 * @magic : index of the mib object
 * @obj   : reference to the corresponding mib object struct
 * @string: static data storage for the string objects
 * @long_ret: static data storage for the integer type objects
 *
 * Returns: void
 */ 
void vxgedev_get_table_object(int magic, struct vxge_data *obj, 
		char *string, long *long_ret)
{
	FILE *f;
	int  obj_offset = 0;
	int  obj_count  = 0;
	int  line_count = 0;
	char line[VXGE_MAX_CHAR_PER_LINE], *p;
	char delim[16] = " ", *token, *save_buf; 

	if (!(f = fopen(VXGE_PROC_DEV_ENTRY, "r"))) {
		vxge_log("%s open error\n", 
				VXGE_PROC_DEV_ENTRY);
		goto err;
	}
	
	while ((p = fgets(line, sizeof(line), f)) 
			&& line_count < obj->table_index)
		line_count++;
	
	if (!p || line_count != obj->table_index) {
		/* should not be here */
		vxge_log("table entry#%d is not found in %s\n",
				obj->table_index, VXGE_PROC_DEV_ENTRY);
		goto err1;
	}
	/* calculate the index of the object in the table */
	obj_offset = magic - VXGE_TABLE_MAGIC_OBJ;
	
	/* parse the row with whitespace and identify the object */
	token = strtok_r(line, delim, &save_buf);
	while (token && obj_count < obj_offset) {
		token = strtok_r(NULL, delim, &save_buf);
		obj_count++;
	}

	if (!token || obj_count != obj_offset) {
		/* control should not be here */
		vxge_log(" object#%d not found in row %d\n",
				magic, obj->table_index);
		goto err1;
	}
	if (obj->vp->type == ASN_OCTET_STR) {
		strcpy(string, token);
		*obj->var_len = strlen(string);
		obj->data = (unsigned char *)string;
	} else {
		*long_ret = strtol(token, NULL, 10);
		obj->data = (unsigned char *)long_ret;
	}
	fclose(f);
	return;

err1:
	fclose(f);
err:
	obj->data = NULL;
}

/*
 * vxgedev_trap_snapshot():
 *      It reads the device table from the proc file
 *      /proc/net/vxge/dev_table and saves the iface info.
 * @trap : trap info structure in which the iface details 
 *         to be saved
 * Returns: Number of iface successfully saved.
 */ 
int vxgedev_trap_snapshot(struct vxge_trap_info *trap)
{
	FILE *f;
	int  obj_offset;
	char line[VXGE_MAX_CHAR_PER_LINE], *p;
	char delim[16] = " ", *token, *save_buf; 

	if (!(f = fopen(VXGE_PROC_DEV_ENTRY, "r"))) {
		vxge_log("%s open error\n", 
				VXGE_PROC_DEV_ENTRY);
		goto err;
	}
	/* skip the header */
	if (!(p = fgets(line, sizeof(line), f))) {
		vxge_log("dev header not found\n");
		goto err1;
	}
	trap->dev_count     = 0;
	trap->link_up_count = 0;
	while ((p = fgets(line, sizeof(line), f))) {
		if (trap->dev_count > VXGE_MAX_DEV)
			break;
		token      = strtok_r(line, delim, &save_buf);
		obj_offset = VXGEDEINDEX;
		while (token && obj_offset <= VXGEDEACTIVELINKSTATE) {
			struct vxge_iface *iface = &trap->dev[trap->dev_count];

			if (obj_offset == VXGEDEINDEX) {
				iface->index = strtol(token, NULL, 10);
			} else if (obj_offset == VXGEDEDESC) {
				strcpy(iface->name, token);
			} else if (obj_offset == VXGEDEACTIVELINKSTATE) {
				iface->link_state = strtol(token, NULL, 10);
				if (iface->link_state)
					trap->link_up_count++;
			}
			token = strtok_r(NULL, delim, &save_buf);
			obj_offset++;
		}
		trap->dev_count++;
	}

	fclose(f);
	return trap->dev_count;

err1:
	fclose(f);
err:
	return -1;
}

