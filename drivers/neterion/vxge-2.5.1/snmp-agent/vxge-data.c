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
 * vxge-data.c : manages and process the mib objects defined for vxge
 */ 

#include <sys/utsname.h>
#include "vxge-agent.h"
#include "vxge-data.h"
#include "vxge-dev.h"

struct vxge_trap_info vxge_trap;

void vxge_get_generic_info(int magic, struct vxge_data *obj, 
		char *string, long *long_ret)
{
	struct utsname name;

	switch (magic) {
	case VXGEGENVENDORNAME:
		strcpy(string, VXGE_VENDOR);
		obj->data = (unsigned char *)string;
		break;
	case VXGEGENPRODUCTDESC:
		strcpy(string, VXGE_PRODUCT);
		obj->data = (unsigned char *)string;
		break;
	case VXGEGENHOSTNAME:
		if (gethostname(string, VXGE_HOST_LEN)) 
			/* on error */
			strcpy(string, VXGE_DEFAULT_HOST);
		else 
			string[VXGE_HOST_LEN + 1] = '\0';			
		obj->data = (unsigned char *)string;
		break;
	case VXGEGENHOSTOS:
		if (uname(&name))
			strcpy(string, VXGE_DEFAULT_HOST);
		else 
			strcpy(string, name.sysname);
		obj->data = (unsigned char *)string;
		break;
	case VXGEGENMIBVERSION:
		strcpy(string, VXGE_MIB_VERSION);
		obj->data = (unsigned char *)string;
		break;
	case VXGEGENVERSION:
		strcpy(string, VXGE_AGENT_VERSION);
		obj->data = (unsigned char *)string;
		break;
	case VXGEGENDRIVERSTATUS:
		*long_ret = vxge_get_driver_status();
		obj->data = (unsigned char *)long_ret;
		break;
	}
	if (obj->vp->type == ASN_OCTET_STR)
		*obj->var_len = strlen(string);
}

unsigned char *
vxge_get_scalar(struct vxge_data *obj)
{
	static long     long_ret;
	//static u_long   ulong_ret;
	static unsigned char string[SPRINT_MAX_LEN];
	//static oid      objid[MAX_OID_LEN];
	//static struct counter64 c64;
	struct variable *vp = obj->vp;
	
	/*
	 * this is where we do the value assignments 
	 * for the mib results.
	 */
	switch (vp->magic) {
	/* fall-through on all generic objects*/
	case VXGEGENVENDORNAME:
	case VXGEGENPRODUCTDESC:
	case VXGEGENHOSTNAME:
	case VXGEGENHOSTOS:
	case VXGEGENMIBVERSION:
	case VXGEGENVERSION:
	case VXGEGENDRIVERSTATUS:
		vxge_get_generic_info(vp->magic, obj, 
				(char *)string, &long_ret);
		break;
	/* fall-through on all base driver objects*/
	case VXGEBDNAME:
	case VXGEBDVERSION:
	case VXGEBDDATE:
	case VXGEBDSPEED:
	case VXGEBDINTRTYPE:
	case VXGEBDDOORBELL:
	case VXGEBDLRO:
	case VXGEBDLROMAXPKT:
	case VXGEBDNAPI:
	case VXGEBDVLANTAGSTRIP:
	case VXGEBDRXSTEERING:
	case VXGEBDTXSTEERING:
		vxgedev_get_base_object(vp->magic, obj,
				(char *)string, &long_ret);
		break;
	case VXGEDEVICEIFACECOUNT:
		long_ret  = vxge_dev_table_size( );
		if (long_ret <= 0)
			long_ret = 0;
		obj->data = (unsigned char *)&long_ret;
		break;
    	case VXGEDTENABLE:
        	*obj->write_method = write_vxgeDTEnable;
		long_ret      = vxge_trap.notify;
        	obj->data     = (unsigned char *)&long_ret;
		break;
	default:
		vxge_log("Unknown object #%d\n", vp->magic);
	}
	return obj->data;
}

unsigned char *
vxge_get_table_entry(struct vxge_data *obj)
{
	static long     long_ret;
	//static u_long   ulong_ret;
	static unsigned char string[SPRINT_MAX_LEN];
	//static oid      objid[MAX_OID_LEN];
	//static struct counter64 c64;
	struct variable *vp = obj->vp;
	
	vxge_log("table entry recieved magic(%d) row(%d)\n", 
			vp->magic, obj->table_index);

	if (vp->magic >= VXGEDEINDEX || vp->magic <= VXGEDETXERRORS) {
		vxgedev_get_table_object(vp->magic, obj, 
				(char *)string, &long_ret);
	} else {
		vxge_log("Unknown table entry #%d\n", 
				vp->magic);
	}
    	return obj->data;
}
/** 
 * trap related functions 
 **/
void vxge_trap_stop(struct vxge_trap_info *trap)
{
	snmp_alarm_unregister(trap->alarm_id);
	memset(trap, 0, sizeof(*trap));
	vxge_log("trap handler stopped...\n");
}

void vxge_trap_check(unsigned int alarm_id,
		void *arg)
{
	struct vxge_trap_info t, *trap;

	if (!(trap = arg)) {
		vxge_log("invalid callback argument\n");
		return;
	}
	if (alarm_id != trap->alarm_id) {
		vxge_log("Unknown alarm id, "
				"exit from trap check\n");
		return;
	}
	if (vxgedev_trap_snapshot(&t) < 0) {
		/*careful! callback removes its own alarm*/
		vxge_trap_stop(trap);
		vxge_log("device info error. trap disabled\n");
		return;
	}
	if (t.dev_count < trap->dev_count) {
		vxgeagent_trap_send(VXGE_TRAP_IFACE_REMOVED);
	} else if (t.dev_count > trap->dev_count) {
		vxgeagent_trap_send(VXGE_TRAP_IFACE_ADDED);
	}

	if (t.link_up_count > trap->link_up_count) {
		vxgeagent_trap_send(VXGE_TRAP_LINK_UP);
	} else if (t.link_up_count < trap->link_up_count) {
		vxgeagent_trap_send(VXGE_TRAP_LINK_DOWN);
	}
	trap->dev_count     = t.dev_count;
	trap->link_up_count = t.link_up_count;
}

void vxge_trap_start(struct vxge_trap_info *trap)
{
	/* save a snapshot of current dev info */
	if (vxgedev_trap_snapshot(trap) < 0) {
		/* this is mostly due to driver not loaded */
		vxge_log("Error on device info. Trap not enabled\n");
		goto out;
	}
	/* register the alarm */
	trap->alarm_id = snmp_alarm_register(VXGE_TRAP_POLL_INTERVAL,
			SA_REPEAT, vxge_trap_check, trap);
	if (!trap->alarm_id) {
		vxge_log("Alarm registration failed\n");
		goto out;
	}
	trap->notify = 1;
	vxge_log("trap handler started...\n");
	return;
out:
	/* reset everything */
	memset(trap, 0, sizeof(*trap));
}

void vxge_trap_manage(struct vxge_trap_info *trap, long enable)
{
	void (*service)(struct vxge_trap_info *trap);

	if (enable && trap->alarm_id) {
		/* unattended alarm, destroy it */
		snmp_alarm_unregister(trap->alarm_id);
		vxge_log("Unattended alarm removed\n");
	}

	service = (enable) ? vxge_trap_start : vxge_trap_stop;

	service(trap);
}
