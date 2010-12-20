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
 * vxge-version.h: Driver for Neterion Inc's X3100 Series 10GbE PCIe I/O
 *                 Virtualized Server Adapter.
 * Copyright(c) 2002-2010 Exar Corp.
 ******************************************************************************/
#ifndef VXGE_VERSION_H

#define VXGE_VERSION_H

#define VXGE_VERSION_MAJOR	"2"
#define VXGE_VERSION_MINOR	"5"
#define VXGE_VERSION_FIX	"1"
#define VXGE_VERSION_BUILD	"22066"
#define VXGE_VERSION_FOR	"p3.5.0.1"

/* firmware file name */
#define VXGE_FW_PXE_FILE_NAME	"X3fw-pxe.ncf"
#define VXGE_FW_FILE_NAME \
		((((fw_upgrade == VXGE_HW_FW_UPGRADE_ALL) && \
		(hldev->eprom_versions[0] == 0)) || \
		(fw_upgrade == VXGE_HW_FW_UPGRADE_WO_PXE_FORCE)) ? \
		"X3fw.ncf" : VXGE_FW_PXE_FILE_NAME)

/* For VMware we use firmware hex array */
#define VXGE_FW_PXE_ARRAY_NAME	X3fw_pxe_ncf
#define VXGE_FW_ARRAY_NAME	X3fw_ncf

#define VXGE_HW_FW_BUF_LEN \
	(((fw_upgrade == VXGE_HW_FW_UPGRADE_ALL) || \
	(fw_upgrade == VXGE_HW_FW_UPGRADE_WO_PXE_FORCE)) ? \
	sizeof(VXGE_FW_ARRAY_NAME) : sizeof(VXGE_FW_PXE_ARRAY_NAME))

#define VXGE_HW_FW_BUF \
	(((fw_upgrade == VXGE_HW_FW_UPGRADE_ALL) || \
	(fw_upgrade == VXGE_HW_FW_UPGRADE_WO_PXE_FORCE)) ? \
	VXGE_FW_ARRAY_NAME : VXGE_FW_PXE_ARRAY_NAME)

#define VXGE_FW_VER(major, minor, build) \
	(((major) << 16) + ((minor) << 8) + (build))

#define VXGE_MAJ_MIN_FW_VER(major, minor)	((major << 16) + (minor << 8))

/* Adapter should be running with below fw_ver for using FW_UPGRADE API's */
#define VXGE_BASE_FW_VER_MAJOR	1
#define VXGE_BASE_FW_VER_MINOR	4
#define VXGE_BASE_FW_VER_BUILD	4

#define VXGE_BASE_FW_VER \
VXGE_FW_VER(VXGE_BASE_FW_VER_MAJOR, VXGE_BASE_FW_VER_MINOR, \
		VXGE_BASE_FW_VER_BUILD)

/* 
 * Certified FW version. 
 * Adapter firmware can only be upgrade to the following version.
 */
#define VXGE_CERT_FW_VER_MAJOR	1
#define VXGE_CERT_FW_VER_MINOR	8
#define VXGE_CERT_FW_VER_BUILD	1

/*
 * Certified gPXE version. Add the rev string with out dots as hex value. 
 * Have '0x' always in the begining
 */
#define VXGE_CERT_EPROM_IMAGE0_VER 0x3300
#define VXGE_CERT_EPROM_IMAGE1_VER 0x0
#define VXGE_CERT_EPROM_IMAGE2_VER 0x0
#define VXGE_CERT_EPROM_IMAGE3_VER 0x0
#define VXGE_CERT_EPROM_IMAGE4_VER 0x0
#define VXGE_CERT_EPROM_IMAGE5_VER 0x0
#define VXGE_CERT_EPROM_IMAGE6_VER 0x0
#define VXGE_CERT_EPROM_IMAGE7_VER 0x0

#define VXGE_EPROM_IMG_MAJOR(val)	vxge_bVALn(val, 48, 4)
#define VXGE_EPROM_IMG_MINOR(val)	vxge_bVALn(val, 52, 4)
#define VXGE_EPROM_IMG_FIX(val)		vxge_bVALn(val, 56, 4)
#define VXGE_EPROM_IMG_BUILD(val)	vxge_bVALn(val, 60, 4)

#define VXGE_CERT_FW_VER \
VXGE_FW_VER(VXGE_CERT_FW_VER_MAJOR, VXGE_CERT_FW_VER_MINOR,\
		 VXGE_CERT_FW_VER_BUILD)

#define VXGE_CERT_MAJ_MIN_FW_VER \
	VXGE_MAJ_MIN_FW_VER(VXGE_CERT_FW_VER_MAJOR, VXGE_CERT_FW_VER_MINOR)

/* for FW_VER >= 1.5.1 COMMIT is required for function mode change */
#define VXGE_COMMIT_REQ_FW_VER	VXGE_FW_VER(1, 5, 1)

#endif
