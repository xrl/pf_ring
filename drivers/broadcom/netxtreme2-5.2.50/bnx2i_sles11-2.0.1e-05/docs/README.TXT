                          Installation Notes
                            Version 1.2.00
                              08/17/2009
                 Broadcom's Linux iSCSI Offload Driver

                          Broadcom Corporation
                         5300 California Avenue,
                            Irvine, CA 92617

                  Copyright (c) 2006-2009 Broadcom Corporation
                           All rights reserved


Table of Contents
=================

  Introduction
  Limitations
  Packaging
  Installing Source RPM Package
  Building Driver From TAR File
  Load and Run Necessary iSCSI Software Components
  BNX2I Driver Dependencies
  BNX2I Driver Parameters
  Unloading and Removing Driver
  Driver Messages
  User Application - 'bnx2id'
  Open-iSCSI User applications
  Bind iSCSI target to Broadcom NX2 iSCSI tranport name
  Making connections to iSCSI Targets
  Maximize Offload iSCSI Connections
  Caveats
  

Introduction
============

This file describes the bnx2i Linux drivers for the Broadcom's
NetXtreme II BCM5706/BCM5708/5709/57710 10/100/1000/2500/10G Mbps PCI/PCI-X/PCIE
CNIC Network Controller. The bnx2i driver enables iSCSI offload on NetXtreme II
family of devices.


Limitations
===========

The current version of the driver has been tested on 2.6.x kernels starting
from 2.6.18 kernel. The driver may not compile on older kernels, one exception
is SLES10 SP1 which run 2.6.16.46 kernel. SUSE upgraded the iscsi_transport
kernel module in SLES10 SP1 and Broadcom iSCSI offload Initiators is supported
on SLES10 SP1. Broadcom QA validation is limited to i386 and x86_64
architectures, Redhat EL5 and SUSE 10 SP1 distributions

Recently Broadcom added support for SLES11U0 running 2.6.27 kernel.


Packaging
=========

The driver is released in two packaging formats: source RPM and compressed tar
formats. The file names for the two packages are netxtreme2-<version>.src.rpm and
netxtreme2-<version>.tar.bz2 respectively. Identical source files to build the
driver are included in both packages. Updated Open-iSCSI components are releases
in source RPM format. Following is a list of files included -

a) netxtreme2-<version>.src.rpm - NetXtreme II L2/cnic/bnx2i driver source RPM
b) bnx2i-<version>.tar.bz2 - tar zipped NetXtreme II L2/cnic/bnx2i driver source
c) README.TXT - This file
d) RELEASE.TXT - release information text providing list of bug fixes and
d) RELEASE_SLES11U0.TXT - release information text providing list of bug fixes and
		enhancement for driver related to SLES11U0
e) LICENSE - Licensing information
f) iscsi-initiator-utils-6.2.0.868-0.7c.src.rpm - OPTIONAL - source RPM,
	updated open-iscsi utils for Redhat EL5.0/5.1/5.2 distribution
g) open-iscsi-2.0.707-0.25b.src.rpm - source RPM, updated open-iscsi components
	for SLES10 SP1 distribution
h) open-iscsi-2.0.707-0.44c.src.rpm - source RPM, updated open-iscsi components
h) open-iscsi-2.0-870.25b.src.rpm - source RPM, updated open-iscsi components
	for SLES10 SP2 distribution


Installing Source RPM Package
=============================

The following are general guidelines for installing the driver.

1. Install the source RPM package:

   # rpm -ivh netxtreme2-<version>.src.rpm

2. change directory to the RPM path and build the binary driver for your kernel:

   # cd /usr/src/{redhat,OpenLinux,turbo,packages,rpm ..}
   # rpmbuild -bb SPECS/netxtreme2.spec

Note that the RPM path is different for different Linux distributions.

The driver will be compiled for the running kernel by default. To build
the driver for a kernel different than the running one, specify the
kernel by defining it in KVER:

   # rpmbuild -bb SPECS/netxtreme2.spec --define "KVER <kernel version>"

where <kernel version> in the form of 2.x.y-z is the version of another
kernel that is installed on the system.

3. Install the newly built package (driver and man page):

   # rpm -ivh RPMS/<arch>/netxtreme2-<version>.<arch>.rpm

where <arch> is the machine architecture such as i386:

   # rpm -ivh RPMS/i386/netxtreme2-<version>.i386.rpm

Note that the --force option may be needed on some Linux distributions
if conflicts are reported.

The driver will be installed in the following path:

2.6.16 and newer kernels:

    /lib/modules/<kernel_version>/kernel/drivers/scsi/bnx2i.ko

	OR

    /lib/modules/<kernel_version>/updates/bnx2i.ko

4. Please refer to section, "Load and Run Necessary iSCSI Software Components",
   on how to load necessary software components required to use Broadcom iSCSI


Building Driver From TAR File
=============================

The following are general guidelines for installing the driver.

1. Create a directory and extract the files:

   tar xvfz netxtreme2-<version>.tar.gz

2. Build the driver bnx2i.ko along with bnx2/bnx2x/cnic drivers as a loadable modules
   for the running kernel:

   # cd netxtreme2-<version>/
   # make clean; make

The driver will be compiled for the running kernel by default. To build
the driver for a kernel different than the running one, specify the
kernel by defining it in KVER:

   # make KVER=<kernel version>

where <kernel version> in the form of 2.x.y-z is the version of another
kernel that is installed on the system.

3. Test the driver by loading it (unload existing driver first if necessary):

   # rmmod bnx2i

   # insmod bnx2i/driver/bnx2i.ko

4. Install the driver and man page:

   make install

See RPM instructions above for the location of the installed driver.

5. install user daemon (bnx2id)
   # cd ${DRV_BASE}/bnx2i/driver
   # make install_usr

This command will install bnx2id binary under '/sbin'

6. Please refer to section, "Load and Run Necessary iSCSI Software Components",
   on how to load necessary software components required to use Broadcom iSCSI
   Offload feature.


Load and Run Necessary iSCSI Software Components
================================================
Broadcom iSCSI Offload software suite consists of 3 kernel modules and
a user daemon. Required software components can be loaded either manually or
through system services -

1. Unload existing driver & kill user daemon if necessary:
Manual:
-------
   # rmmod bnx2i
   # pkill -9 bnx2id

Using service:
--------------
   # service bnx2id stop

2. Load iscsi driver & the user daemon:
Manual:
-------
   # bnx2id
   # insmod bnx2i.ko
or
   # modprobe bnx2i

Using service:
--------------
   # service bnx2id start


BNX2I Driver Dependencies
=========================

The driver uses library functions in the scsi_transport_iscsi, bnx2, bnx2x,
cnic and ipv6.ko. It is required to load these library modules either as
loadable module or as kernel built-in component before attempting to load
the driver or unresolved symbol errors will appear. Using modprobe will
resolve the dependencies automatically.


BNX2I Module Parameters
======================

optional parameters "en_tcp_dack", "error_mask1", and "error_mask2"
can be supplied as a command line arguments to the insmod or modprobe
command for bnx2i.

----------------------------
error_mask1 and error_mask2:
----------------------------
Description: "Config FW iSCSI Error Mask #", use to configure
	certain iSCSI protocol violation to treated either as warning
	or fatal error. All fatal iSCSI protocol voilations will result
	in session recovery (ERL 0). These are bit masks

Defaults: All violation will be treated as errors. 

CAUTION: Do not meddle with 'error_mask' if you are not sure about the
	consequences. These values are to be discussed with Broadcom
	development team on case by case basic. This is just a mechanism
	to work around iSCSI implementation issues on the target side and
	without proper knowledge of iSCSI protocol details, user are advised
	not to experiment with these parameters


------------
en_tcp_dack:
------------
Description: "Enable TCP Delayed ACK", enables/disables TCP delayed ACK
	feature on offloaded iSCSI connections

Defaults: TCP delayed ACK is ENABLED

e.g.
	# insmod bnx2i.ko en_tcp_dack=0
		or
	# modprobe bnx2i en_tcp_dack=0


--------
sq_size:
--------
Description: "Configure SQ size", used to choose send queue size for offloaded
	connections and SQ size determines maximum SCSI commands that can be
	queued. SQ size also has a bearing on the number of connections that can
	be offloaded, as QP size increases, number of connections supported will
	decrease. With default values, 5706/5708 can offload 28 connections.

Defaults: 128
Range: 32 to 128
Note: Broadcom validation is limited to power of 2, e.g. 32, 64, 128


--------
rq_size:
--------
Description: "Configure RQ size", used to choose size of asynchronous buffer
	queue size per offloaded connections and RQ size is not required be
	greater than 16 as it is used to place iSCSI ASYNC/NOP/REJECT messages
	and SCSI sense data.

Defaults: 16
Range: 16 to 32
Note: Broadcom validation is limited to power of 2, e.g. 16, 32


----------------
event_coal_div :
----------------
Description: "Event Coalescing Divide Factor", performance tuning parameter
	used to moderate the rate of interrupt generation by the iscsi firmware

Defaults: 1
Valid Values: 1,2,4,8
Note: Broadcom did find a single digit improvement in IOPS numbers on 1G chips
	But Broadcom has decided to disable interrupt coalescing for
	5706/5708/5709 as our IOPS numbers are more than double the competition.
	However we believe this parameter makes more sense to 57710 (10G)


-----------------------------------
bnx2i_nopout_when_commands_active :
-----------------------------------
Description: "iSCSI NOOP even when connection is not idle", this parameter
	enables offload initiator to send iSCSI NOP-OUT on wire even when
	the link is not truely idle. This was introduced to avoid unnecessary
	session recoveries induced by some older targets when iSCSI NOP-OUT &
	iSCSI CMD pdus are intermixed. Newer iSCSI target systems are immune
	to this condition and this parameter is turned ON for quite some time.
Defaults: 1
Values: Binary parameter, 0/1


The parameters can also be set in modprobe.conf. See the man page
for more information.


Unloading and Removing Driver
=============================

To unload the driver, disconnect all active iSCSI sessions to targets and run
the following command -

rmmod bnx2i

NOTE: refer to open-iscsi CLI tool, 'iscsiadm' for session teardown instructions

If the driver was installed using rpm, do the following to remove it:

rpm -e bnx2i


If the driver was installed using make install from the tar file, the driver
bnx2i.ko has to be manually deleted from the system. Refer to the section
"Installing Source RPM Package" for the location of the installed driver.


Driver Messages
===============

The following are the most common sample messages that may be logged in the file
/var/log/messages. Use dmesg -n <level> to control the level at which messages
will appear on the console. Most systems are set to level 6 by default. To see
all messages, set the level higher.

BNX2I Driver signon:
-------------------

Broadcom NetXtreme II iSCSI Driver bnx2i v1.0.30 (Sep 29, 2007)


Network port to iSCSI transport name binding:
---------------------------------------------

bnx2i: netif=eth2, iscsi=bcm570x-050000
bnx2i: netif=eth1, iscsi=bcm570x-030c00


Driver completes handshake with iSCSI Offload Enabled CNIC device:
------------------------------------------------------------------

bnx2i [05:00.00]: ISCSI_INIT passed

NOTE: this message is displayed only when user attempts to make an
iSCSI connection


Driver detects iSCSI Offload is not enabled on the CNIC device:
---------------------------------------------------------------

bnx2i: iSCSI not supported, dev=eth3
bnx2i: bnx2i: LOM is not enabled to offload iSCSI connections, dev=eth0


Driver unable to allocate TCP port for iSCSI connection:
--------------------------------------------------------

bnx2i: unable to allocate tcp ports, make sure 'bnx2id' is running



Exceeds maximum allowed iSCSI connection offload limit:
-------------------------------------------------------

bnx2i: unable to allocate iSCSI context resources



Network route to target node and transport name binding are 2 different devices:
--------------------------------------------------------------------------------

bnx2i: conn bind, ep=0x... ($ROUTE_HBA) does not belong to hba $USER_CHOSEN_HBA
	where 	ROUTE_HBA --> net device on which connection was offloaded
				based on route information
		USER_CHOSEN_HBA --> HBA to which target node is bound (using
				iscsi transport name)


Target cannot be reached on any of CNIC devices:
------------------------------------------------

bnx2i: check route, can't connect using cnic



Network route is assigned to network interfce which is down:
------------------------------------------------------------

bnx2i: check route, hba not found


Attempting to offload iSCSI connection onto Jumbo frame enabled device:
-----------------------------------------------------------------------

bnx2i: eth# network i/f mtu is set to #mtu
bnx2i: iSCSI HBA can support mtu of 1500
NOTE: user has to change 'mtu' to < 1500 using 'ifconfig' and restart the
	the interface in order to offload iSCSI connections


SCSI-ML initiated host reset (session recovery):
------------------------------------------------

bnx2i: attempting to reset host, #3


CNIC detects iSCSI protocol violation - FATAL errors:
-----------------------------------------------------

bnx2i: iscsi_error - wrong StatSN rcvd
bnx2i: iscsi_error - hdr digest err
bnx2i: iscsi_error - data digest err
bnx2i: iscsi_error - wrong opcode rcvd
bnx2i: iscsi_error - AHS len > 0 rcvd
bnx2i: iscsi_error - invalid ITT rcvd
bnx2i: iscsi_error - wrong StatSN rcvd
bnx2i: iscsi_error - wrong DataSN rcvd
bnx2i: iscsi_error - pend R2T violation
bnx2i: iscsi_error - ERL0, UO
bnx2i: iscsi_error - ERL0, U1
bnx2i: iscsi_error - ERL0, U2
bnx2i: iscsi_error - ERL0, U3
bnx2i: iscsi_error - ERL0, U4
bnx2i: iscsi_error - ERL0, U5
bnx2i: iscsi_error - ERL0, U
bnx2i: iscsi_error - invalid resi len
bnx2i: iscsi_error - MRDSL violation
bnx2i: iscsi_error - F-bit not set
bnx2i: iscsi_error - invalid TTT
bnx2i: iscsi_error - invalid DataSN
bnx2i: iscsi_error - burst len violation
bnx2i: iscsi_error - buf offset violation
bnx2i: iscsi_error - invalid LUN field
bnx2i: iscsi_error - invalid R2TSN field
bnx2i: iscsi_error - invalid cmd len1
bnx2i: iscsi_error - invalid cmd len2
bnx2i: iscsi_error - pend r2t exceeds MaxOutstandingR2T value
bnx2i: iscsi_error - TTT is rsvd
bnx2i: iscsi_error - MBL violation
bnx2i: iscsi_error - data seg len != 0
bnx2i: iscsi_error - reject pdu len error
bnx2i: iscsi_error - async pdu len error
bnx2i: iscsi_error - nopin pdu len error
bnx2i: iscsi_error - pend r2t in cleanup
bnx2i: iscsi_error - IP fragments rcvd
bnx2i: iscsi_error - IP options error
bnx2i: iscsi_error - urgent flag error


CNIC detects iSCSI protocol violation - non-FATAL, warning:
-----------------------------------------------------------

bnx2i: iscsi_warning - invalid TTT
bnx2i: iscsi_warning - invalid DataSN
bnx2i: iscsi_warning - invalid LUN field

NOTE: driver by default is configured to consider certain violation to be
treated as warning and not as errors


Driver puts a session through recovery:
---------------------------------------

conn_err - hostno 3 conn 03fbcd00, iscsi_cid 2 cid a1800


REJECT iSCSI PDU recieved from the target:
------------------------------------------

bnx2i - printing rejected PDU contents
[0]: 1 ffffffa1 0 0 0 0 20 0
[8]: 0 7 0 0 0 0 0 0
[10]: 0 0 40 24 0 0 ffffff80 0
[18]: 0 0 3 ffffff88 0 0 3 4b
[20]: 2a 0 0 2 ffffffc8 14 0 0
[28]: 40 0 0 0 0 0 0 0


Open-iSCSI daemon handing over session to driver:
-------------------------------------------------
bnx2i: conn update - MBL 0x800 FBL 0x800MRDSL_I 0x800 MRDSL_T 0x2000 



User Application - 'bnx2id':
==============================

'bnx2id' application should be installed under '/sbin' when bnx2i RPM package
is installed.  Refer to the section "Installing Source RPM Package" for
information.  Run 'bnx2id' daemon before attempting to create iSCSI connections
Driver won't be able to establish connections to iSCSI target without daemon's
assistance

	# bnx2id

bnx2id daemon requires mknod and sh shell, which are pretty much standard on
any regular server. For iSCSI boot using NX2 offload support, binaries for
'mknod' and 'sh' needs to be bundled into initrd image.


Open-iSCSI User applications:
=============================

Install and run open-iscsi programs, 'iscsid' & 'iscsiadm' from Broadcom
distributed open-iscsi packages, refer to "Packaging" section for more
details. All pre-installed open-iscsi packages needs to be removed before
Broadcom iSCSI supported packages could be installed.

Redhat EL 5.0, 5.1, 5.2 -
open-iscsi-package-name = iscsi-initiator-utils-6.2.0.868-0.7d

Redhat EL 5.3
open-iscsi-package-name = iscsi-initiator-utils-6.2.0.868-0.18b

SLES10 SP1 -
open-iscsi-package-name = open-iscsi-2.0.707-0.25b

SLES10 SP2 -
open-iscsi-package-name = open-iscsi-2.0.707-0.44e

SLES11 SP0 -
open-iscsi-package-name = open-iscsi-2.0-870.26.5b

1. Remove all existing open-iscsi packages:
   
   RHEL5 -
   # rpm -e iscsi-initiator-utils

   SLES10 SP1 -
   # rpm -e open-iscsi

2. Install the source RPM package:

   # rpm -ivh <open-iscsi-package-name>.src.rpm


3. CD to the RPM path and build the binary driver for your kernel:

   # cd /usr/src/{redhat,OpenLinux,turbo,packages,rpm ..}
   # rpmbuild -bb SPECS/<open-iscsi-package-name>.spec

Note that the RPM path is different for different Linux distributions.

4. Install the newly built package :

   # rpm -ivh RPMS/<arch>/<open-iscsi-package-name>.<arch>.rpm

where <arch> is the machine architecture such as i386:

   # rpm -ivh RPMS/i386/<open-iscsi-package-name>.i386.rpm

5. Start the daemon
   # iscsid


Making connections to iSCSI Targets:
====================================

Please refer to open-iscsi documentation for comprehensive list of 'iscsiadm'
commands. Here is a sample list of commands to discover targets and
create iscsi connections to target.

*** Note - With iscsid v2.0-754 (open-iscsi-2.0.707-0.25b which is bundled for use
with SLES10 SP1), the transport name is specified as 'node.transport_name' instead
of 'iface.transport_name'.  Also, the target portal group tag (TPGT) is not used. 
With the open-iscsi initiators bundled for use with Redhat and SLES10 SP2, the 
target portal group tag (TPGT) is needed if the user is creating a static entry ***


Add static entry:
-----------------

	# iscsiadm -m node -p <ipaddr[:port],TPGT> -T <iqn.targetname> -o new 


iSCSI target discovery using 'SendTargets':
-------------------------------------------

	# iscsiadm -m discovery --type sendtargets -p <ipaddr[:port]> 


Bind iSCSI target to Broadcom NX2 transport (see next section for obtaining the transport name) :
-------------------------------------------

	# iscsiadm -m node -p <ipaddr[:port]> -T <iqn.targetname> --op=update 
		--name=iface.transport_name --value=${XPORT_NAME}


Login to target using 'iscsiadm' command:
-----------------------------------------

	# iscsiadm -mode node -p <ipaddr[:port]> -T <iqn.targetname> --login


List all drives active in the system:
-------------------------------------
	# fdisk -l


Bind iSCSI target to Broadcom NX2 iSCSI tranport name:
======================================================

*** Note - With iscsid v2.0-754 (open-iscsi-2.0.707-0.25b which is bundled for use
with SLES10 SP1), the transport option is specified as 'node.transport_name' instead
of 'iface.transport_name'. ***

By default open-iscsi daemon connects to discovered targets using software
initiatior (transport name = 'tcp'). Users who wish to offload iSCSI connection
onto CNIC device should explicitly change transport binding of the iSCSI node.
This can be easily done using 'iscsiadm' cli utlity as follows,

	# iscsiadm --mode node --targetname iqn.2004-06.com.broadcom:tg1 \
		--portal 192.168.1.100 --op=update			 \
		--name=iface.transport_name --value=${XPORT_NAME}

where XPORT_NAME=bcm570x-xxyyzz
	xx - pci bus number of the NX2 device
	yy - pci device number of the NX2 device
	zz - pci function number of the NX2 device

Network interface to iscsi transport name binding can be obtained by executing,
	# dmesg | grep "bnx2i: netif"

Sample output in a system with 2 NetXtreme II devices -
	bnx2i: netif=eth1, iscsi=bcm570x-050000
	bnx2i: netif=eth0, iscsi=bcm570x-030000

If user wishes to switch back to use software initiator for whatever reason,
following command will do the trick,
	# iscsiadm --mode node --targetname iqn.2004-06.com.broadcom:tg1 \
		--portal 192.168.1.100 --op=update			 \
		--name=iface.transport_name --value=tcp


Maximize iSCSI Offload Connections:
===================================
With default driver parameter set which includes 128 outsanding commands, bnx2i
can offload a maximum of 28 iSCSI connections. This is no hard limit, just a simple
on chip resource allocation math. bnx2i will be able to offload > 28 connections
by reducing the shared queue size which in turn limits the maximum outstanding
tasks on a connection. Refer to section "BNX2I Module Parameters" for further
details on sq_size, rq_size and cq_size.
Driver logs the following message to syslog when maximum allowed connection
offload limit is reached - "bnx2i: unable to allocate iSCSI context resources"


Caveats:
========

1. iSCSI support on CNIC devices:
---------------------------------

Not all Broadcom NetExteme II device support iSCSI offload, please contact
your server manufacturer on instructions to enable iSCSI offload


2) iSCSI Session won't recover after hot remove and hotplug:
------------------------------------------------------------

   Cause is successive device registration with iSCSI transport layer would
result in different 64-bithandles. Also when the device is removed, route
could resolve to a different CNIC port in which case iSCSI session/connection
are bound to HBA 1 (which just got hot removed) and TCP connection is
established on HBA 2 and this is not an acceptable configuration. Broadcom
advises administrator to logoff all iSCSI session before removing the HBA from
the server


3. iSCSI Session recovery due to network device oparation:
----------------------------------------------------------

Following popular network device operations will result in iSCSI connection
teardown, in most cases connection will recover but sometime it may not
depending on the network configuration,
  a) Ethernet interface reset
	# service network restart
	# ifdown eth#; ifup eth#

  b) Change IP address
	# ifconfig eth0 192.168.1.20

  c) MTU change
	# ifconfig eth0 mtu 1000 up

  d) ethtool selftest
	# ethtool -t eth0


4. Jumbo frames not supported:
------------------------------

iSCSI driver/firmware will not offload iSCSI connection on a jumbo frame enabled
CNIC device. Refer to section "Driver Messages", sub-section "Attempting to
offload iSCSI connection onto Jumbo frame enabled device" for more details.


5. MPIO using open-iscsi needs pro-active iSCSI nopout's enabled:
-----------------------------------------------------------------
For MPIO to work properly iSCSI nopout should be enabled on each iSCSI session.
Please refer to open-iscsi documentation on how to set 'noop_out_interval' and
'noop_out_timeout' values. Default values could be differ between releases and
is advisible to set them to 10 sec and 15 secs respectively


6. iSCSI boot using iSCSI Offload and multiple CNIC devices issue:
------------------------------------------------------------------
If there are multiple CNIC devices in the system and system is booted via'
Broadcom's iSCSI boot solution, use has to make sure iscsi node under
/etc/iscsi/nodes for the boot target is bound to NIC which is used for booting.
If there is a mis-match in this configuration system will hang when boot
session gets into recovery mode.
e.g.
NIC1 : net device = eth0, transport name = bcm570x-030200
NIC2 : net device = eth1, transport name = bcm570x-050000
boot target : name = iqn.2007-10.com.broadcom:target1, portal = 192.168.0.10:3260

If administrator chooses to boot using NIC1, parameter 'node.transport_name ='
in file /etc/iscsi/nodes/iqn.2007-10.com.broadcom:target1/192.168.0.10:3260
should be set to 'bcm570x-030200'. Refer to section "Bind iSCSI target to
Broadcom NX2 iSCSI tranport name" for more information on iscsi transport names
