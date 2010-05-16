/* bnx2i_hwi.c: Broadcom NetXtreme II iSCSI driver.
 *
 * Copyright (c) 2006 - 2009 Broadcom Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 *
 * Written by: Anil Veerabhadrappa (anilgv@broadcom.com)
 */

#include "bnx2i.h"
#include "bnx2i_ioctl.h"

#include <asm/compat.h>

#ifdef _BNX2I_IOCTL_

static int bnx2i_major_no;
struct tcp_port_mngt bnx2i_tcp_port_tbl;
static DEFINE_SPINLOCK(bnx2i_resc_lock); /* protects global resources */
struct file_operations bnx2i_mgmt_fops;

/**
 * bnx2i_alloc_tcp_port - allocates a tcp port from the free list
 *
 * assumes this function is called with 'bnx2i_resc_lock' held
 **/
u16 bnx2i_alloc_tcp_port(void)
{
	u16 tcp_port;

	if (!bnx2i_tcp_port_tbl.num_free_ports || !bnx2i_tcp_port_tbl.free_q)
		return 0;

	tcp_port = bnx2i_tcp_port_tbl.free_q[bnx2i_tcp_port_tbl.cons_idx];
	bnx2i_tcp_port_tbl.cons_idx++;
	bnx2i_tcp_port_tbl.cons_idx %= bnx2i_tcp_port_tbl.max_idx;
	bnx2i_tcp_port_tbl.num_free_ports--;

	return tcp_port;
}


/**
 * bnx2i_free_tcp_port - Frees the given tcp port back to free pool
 *
 * @port: 		tcp port number being freed
 *
 * assumes this function is called with 'bnx2i_resc_lock' held
 **/
void bnx2i_free_tcp_port(u16 port)
{
	if (!bnx2i_tcp_port_tbl.free_q)
		return;

	bnx2i_tcp_port_tbl.free_q[bnx2i_tcp_port_tbl.prod_idx] = port;
	bnx2i_tcp_port_tbl.prod_idx++;
	bnx2i_tcp_port_tbl.prod_idx %= bnx2i_tcp_port_tbl.max_idx;
	bnx2i_tcp_port_tbl.num_free_ports++;
}

/**
 * bnx2i_tcp_port_new_entry - place 'bnx2id' allocated tcp port number
 *		to free list
 *
 * @port: 		tcp port number being added to free pool
 *
 * 'bnx2i_resc_lock' is held while operating on global tcp port table
 **/
void bnx2i_tcp_port_new_entry(u16 tcp_port)
{
	u32 idx = bnx2i_tcp_port_tbl.prod_idx;

	spin_lock(&bnx2i_resc_lock);
	bnx2i_tcp_port_tbl.free_q[idx] = tcp_port;
	bnx2i_tcp_port_tbl.prod_idx++;
	bnx2i_tcp_port_tbl.prod_idx %= bnx2i_tcp_port_tbl.max_idx;
	bnx2i_tcp_port_tbl.num_free_ports++;
	bnx2i_tcp_port_tbl.num_required--;
	spin_unlock(&bnx2i_resc_lock);
}

/**
 * bnx2i_init_tcp_port_mngr - initializes tcp port manager
 *
 */
void bnx2i_init_tcp_port_mngr(void)
{
	int mem_size;

	bnx2i_tcp_port_tbl.num_free_ports = 0;
	bnx2i_tcp_port_tbl.prod_idx = 0;
	bnx2i_tcp_port_tbl.cons_idx = 0;
	bnx2i_tcp_port_tbl.max_idx = 0;
	bnx2i_tcp_port_tbl.num_required = 256;
//printk("bnx2i: ioctl mngr - %d\n", bnx2i_tcp_port_tbl.num_required);

#define BNX2I_MAX_TCP_PORTS	1024

	bnx2i_tcp_port_tbl.port_tbl_size = BNX2I_MAX_TCP_PORTS;

	mem_size = sizeof(u16) * bnx2i_tcp_port_tbl.port_tbl_size;
	if (bnx2i_tcp_port_tbl.port_tbl_size) {
		bnx2i_tcp_port_tbl.free_q = kmalloc(mem_size, GFP_KERNEL);

		if (bnx2i_tcp_port_tbl.free_q)
			bnx2i_tcp_port_tbl.max_idx =
				bnx2i_tcp_port_tbl.port_tbl_size;
	}
}


/**
 * bnx2i_cleanup_tcp_port_mngr - frees memory held by global tcp port table
 *
 */
void bnx2i_cleanup_tcp_port_mngr(void)
{
	kfree(bnx2i_tcp_port_tbl.free_q);
	bnx2i_tcp_port_tbl.free_q = NULL;
	bnx2i_tcp_port_tbl.num_free_ports = 0;
}



int bnx2i_check_ioctl_signature(struct bnx2i_ioctl_header *ioc_hdr)
{
	if (strcmp(ioc_hdr->signature, BNX2I_MGMT_SIGNATURE))
		return -EPERM;
	return 0;
}

static int bnx2i_tcp_port_count_ioctl(struct file *file, unsigned long arg)
{
	struct bnx2i_get_port_count __user *user_ioc =
		(struct bnx2i_get_port_count __user *)arg;
	struct bnx2i_get_port_count ioc_req;
	int error = 0;
	unsigned int count = 0;

//printk("bnx2i: ioctl port req - %d\n", bnx2i_tcp_port_tbl.num_required);

	if (copy_from_user(&ioc_req, user_ioc, sizeof(ioc_req))) {
		error = -EFAULT;
//printk("bnx2i: ioctl - unable to copy from user\n");
		goto out;
	}

	error = bnx2i_check_ioctl_signature(&ioc_req.hdr);
	if (error) {
printk("bnx2i: ioctl - signature check failed!!\n");
		goto out;
	}

	if (bnx2i_tcp_port_tbl.num_free_ports < 10 &&
	    bnx2i_tcp_port_tbl.num_required) {
		if (bnx2i_tcp_port_tbl.num_required < 32) {
			count = bnx2i_tcp_port_tbl.num_required;
		} else {
			count = 32;
		}
	}
//printk("bnx2i: ioctl - num port %d\n", count);

	ioc_req.port_count = count;

	if (copy_to_user(&user_ioc->port_count, &ioc_req.port_count,
			 sizeof(ioc_req.port_count))) {
		error = -EFAULT;
		goto out;
	}

out:
	return error;
}


static int bnx2i_tcp_port_ioctl(struct file *file, unsigned long arg)
{
	struct bnx2i_set_port_num __user *user_ioc =
		(struct bnx2i_set_port_num __user *)arg;
	struct bnx2i_set_port_num ioc_req;
	struct bnx2i_set_port_num *ioc_req_mp = NULL;
	int ioc_msg_size = sizeof(ioc_req);
	int error;
	int i;

	if (copy_from_user(&ioc_req, user_ioc, ioc_msg_size)) {
		error = -EFAULT;
		goto out;
	}

	error = bnx2i_check_ioctl_signature(&ioc_req.hdr);
	if (error)
		goto out;

	if (ioc_req.num_ports > 1) {
		ioc_msg_size += (ioc_req.num_ports - 1) *
				sizeof(ioc_req.tcp_port[0]);

		ioc_req_mp = kmalloc(ioc_msg_size, GFP_KERNEL);
		if (!ioc_req_mp)
			goto out;

		if (copy_from_user(ioc_req_mp, user_ioc, ioc_msg_size)) {
			error = -EFAULT;
			goto out_kfree;
		}
	}

	if (ioc_req.num_ports)
		bnx2i_tcp_port_new_entry(ioc_req.tcp_port[0]);

//printk("bnx2i: ioctl - num ports %d\n", ioc_req_mp->num_ports);
	i = 1;
	while (i < ioc_req_mp->num_ports)
		bnx2i_tcp_port_new_entry(ioc_req_mp->tcp_port[i++]);

	return 0;

out_kfree:
	kfree(ioc_req_mp);
out:
	return error;
}


/*
 * bnx2i_ioctl_init: initialization routine, registers char driver
 */
int bnx2i_ioctl_init(void)
{
	int ret;

        /* Register char device node */
        ret = register_chrdev(0, "bnx2i", &bnx2i_mgmt_fops);

        if (ret < 0) {
                printk(KERN_ERR "bnx2i: failed to register device node\n");
                return ret;
        }

        bnx2i_major_no = ret;
	bnx2i_init_tcp_port_mngr();

	return 0;
}

void bnx2i_ioctl_cleanup(void)
{
	if (bnx2i_major_no)
		unregister_chrdev(bnx2i_major_no, "bnx2i");

	bnx2i_cleanup_tcp_port_mngr();
}

/*
 * bnx2i_mgmt_open -  "open" entry point
 */
static int bnx2i_mgmt_open(struct inode *inode, struct file *filep)
{
        /* only allow access to admin user */
        if (!capable(CAP_SYS_ADMIN)) {
                return -EACCES;
	}

        return 0;
}

/*
 * bnx2i_mgmt_release- "release" entry point
 */
static int bnx2i_mgmt_release(struct inode *inode, struct file *filep)
{
        return 0;
}



/*
 * bnx2i_mgmt_ioctl - char driver ioctl entry point
 */
static int bnx2i_mgmt_ioctl(struct inode *node, struct file *file,
			    unsigned int cmd, unsigned long arg)
{
	long rc = 0;
	switch (cmd) {
		case BNX2I_IOCTL_GET_PORT_REQ:
			rc = bnx2i_tcp_port_count_ioctl(file, arg);
			break;
		case BNX2I_IOCTL_SET_TCP_PORT:
			rc = bnx2i_tcp_port_ioctl(file, arg);
			break;
		default:
			printk(KERN_ERR "bnx2i: unknown ioctl cmd %x\n", cmd);
			return -ENOTTY;
	}

	return rc;
}


#ifdef CONFIG_COMPAT

static int bnx2i_tcp_port_count_compat_ioctl(struct file *file, unsigned long arg)
{
	struct bnx2i_get_port_count __user *user_ioc =
		(struct bnx2i_get_port_count __user *)arg;
	struct bnx2i_get_port_count *ioc_req =
		compat_alloc_user_space(sizeof(struct bnx2i_get_port_count));
	int error;
	unsigned int count = 0;

	if (clear_user(ioc_req, sizeof(*ioc_req)))
		return -EFAULT;

	if (copy_in_user(ioc_req, user_ioc, sizeof(*ioc_req))) {
		error = -EFAULT;
		goto out;
	}

	error = bnx2i_check_ioctl_signature(&ioc_req->hdr);
	if (error)
		goto out;

	if (bnx2i_tcp_port_tbl.num_free_ports < 10 &&
	    bnx2i_tcp_port_tbl.num_required) {
		if (bnx2i_tcp_port_tbl.num_required < 32)
			count = bnx2i_tcp_port_tbl.num_required;
		else
			count = 32;
	}

	if (copy_to_user(&ioc_req->port_count, &count,
			 sizeof(ioc_req->port_count))) {
		error = -EFAULT;
		goto out;
	}

	if (copy_in_user(&user_ioc->port_count, &ioc_req->port_count,
			 sizeof(u32))) {
		error = -EFAULT;
		goto out;
	}
	return 0;

out:
	return error;
}

static int bnx2i_tcp_port_compat_ioctl(struct file *file, unsigned long arg)
{
	struct bnx2i_set_port_num __user *user_ioc =
		(struct bnx2i_set_port_num __user *)arg;
	struct bnx2i_set_port_num *ioc_req =
		compat_alloc_user_space(sizeof(struct bnx2i_set_port_num));
	struct bnx2i_set_port_num *ioc_req_mp = NULL;
	int ioc_msg_size = sizeof(*ioc_req);
	int error;
	int i;

	if (clear_user(ioc_req, sizeof(*ioc_req)))
		return -EFAULT;

	if (copy_in_user(ioc_req, user_ioc, ioc_msg_size)) {
		error = -EFAULT;
		goto out;
	}

	error = bnx2i_check_ioctl_signature(&ioc_req->hdr);
	if (error)
		goto out;

	if (ioc_req->num_ports > 1) {
		ioc_msg_size += (ioc_req->num_ports - 1) *
				sizeof(ioc_req->tcp_port[0]);

		ioc_req_mp = compat_alloc_user_space(ioc_msg_size);
		if (!ioc_req_mp)
			goto out;

		if (copy_in_user(ioc_req_mp, user_ioc, ioc_msg_size)) {
			error = -EFAULT;
			goto out;
		}
//printk("bnx2i: ioctl - num ports %d\n", ioc_req_mp->num_ports);

		i = 0;
		while ((i < ioc_req_mp->num_ports) && ioc_req_mp)
			bnx2i_tcp_port_new_entry(ioc_req_mp->tcp_port[i++]);

	} else if (ioc_req->num_ports == 1)
		bnx2i_tcp_port_new_entry(ioc_req->tcp_port[0]);

out:
	return error;


}


/*
 * bnx2i_mgmt_compat_ioctl - char node ioctl entry point
 */
static long bnx2i_mgmt_compat_ioctl(struct file *file,
				    unsigned int cmd, unsigned long arg)
{
	int rc = -ENOTTY;

	switch (cmd) {
		case BNX2I_IOCTL_GET_PORT_REQ:
			rc = bnx2i_tcp_port_count_compat_ioctl(file, arg);
			break;
		case BNX2I_IOCTL_SET_TCP_PORT:
			rc = bnx2i_tcp_port_compat_ioctl(file, arg);
			break;
	}

        return rc;
}

#endif

/*
 * File operations structure - management interface
 */
struct file_operations bnx2i_mgmt_fops = {
        .owner = THIS_MODULE,
        .open = bnx2i_mgmt_open,
        .release = bnx2i_mgmt_release,
        .ioctl = bnx2i_mgmt_ioctl,
#ifdef CONFIG_COMPAT
        .compat_ioctl = bnx2i_mgmt_compat_ioctl,
#endif
};

#endif		/* _BNX2I_IOCTL_ */
