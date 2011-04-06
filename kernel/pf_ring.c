/* ***************************************************************
 *
 * (C) 2004-11 - Luca Deri <deri@ntop.org>
 *
 * This code includes contributions courtesy of
 * - Amit D. Chaudhary <amit_ml@rajgad.com>
 * - Andrew Gallatin <gallatyn@myri.com>
 * - Brad Doctor <brad@stillsecure.com>
 * - Felipe Huici <felipe.huici@nw.neclab.eu>
 * - Francesco Fusco <fusco@ntop.org> (IP defrag)
 * - Helmut Manck <helmut.manck@secunet.com>
 * - Hitoshi Irino <irino@sfc.wide.ad.jp> (IPv6 support)
 * - Jakov Haron <jyh@cabel.net>
 * - Jeff Randall <jrandall@nexvu.com>
 * - Kevin Wormington <kworm@sofnet.com>
 * - Mahdi Dashtbozorgi <rdfm2000@gmail.com>
 * - Marketakis Yannis <marketak@ics.forth.gr>
 * - Matthew J. Roth <mroth@imminc.com>
 * - Michael Stiller <ms@2scale.net> (VM memory support)
 * - Noam Dev <noamdev@gmail.com>
 * - Siva Kollipara <siva@cs.arizona.edu>
 * - Vincent Carrier <vicarrier@wanadoo.fr>
 * - Eugene Bogush <b_eugene@ukr.net>
 * - Samir Chang <coobyhb@gmail.com>
 * - Ury Stankevich <urykhy@gmail.com>
 * - Raja Mukerji <raja@mukerji.com>
 * - Davide Viti <zinosat@tiscali.it>
 * - Will Metcalf <william.metcalf@gmail.com>
 * - Godbach <nylzhaowei@gmail.com>
 * - Nicola Bonelli <bonelli@antifork.org>
 * - Jan Alsenz
 * - valxdater@seznam.cz
 * - Vito Piserchia <vpiserchia@metatype.it>
 * - Guo Chen <johncg1983@gmail.com>
 * - Dan Kruchinin <dkruchinin@acm.org>
 * - Andreas Tsopelas <tsopelas@kth.se>
 * - Alfredo Cardigliano <cardigliano@ntop.org>
 * - Alex Aronson <alexa@silicom.co.il>
 * - Piotr Romanus <promanus@crossbeamsys.com>
 * - Lior Okman <lior.okman@insightix.com>
 * - Fedor Sakharov <fedor.sakharov@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */

#include <linux/version.h>

#if(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18))
#error **********************************************************************
#error * PF_RING works on kernel 2.6.18 or newer. Please update your kernel *
#error **********************************************************************
#endif


#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18))
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33))
#include <generated/autoconf.h>
#else
#include <linux/autoconf.h>
#endif
#else
#include <linux/config.h>
#endif
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/kernel.h>
#include <linux/socket.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/in6.h>
#include <linux/init.h>
#include <linux/filter.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/list.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/proc_fs.h>
#include <linux/if_arp.h>
#include <net/xfrm.h>
#include <net/sock.h>
#include <asm/io.h>		/* needed for virt_to_phys() */
#ifdef CONFIG_INET
#include <net/inet_common.h>
#endif
#include <net/ip.h>
#include <net/ipv6.h>

#if(LINUX_VERSION_CODE > KERNEL_VERSION(2,6,22))
#include <linux/eventfd.h> /* needed by vPFRing */
#endif

#include <linux/pf_ring.h>

#ifndef SVN_REV
#define SVN_REV ""
#endif

/* ************************************************* */

#define TH_FIN_MULTIPLIER	0x01
#define TH_SYN_MULTIPLIER	0x02
#define TH_RST_MULTIPLIER	0x04
#define TH_PUSH_MULTIPLIER	0x08
#define TH_ACK_MULTIPLIER	0x10
#define TH_URG_MULTIPLIER	0x20

/* ************************************************* */

#define PROC_INFO               "info"
#define PROC_DEV                "dev"
#define PROC_RULES              "rules"
#define PROC_PLUGINS_INFO       "plugins_info"

/* ************************************************* */

const static ip_addr ip_zero = { IN6ADDR_ANY_INIT };

static u_int8_t pfring_enabled = 0;

/* Dummy 'any' device */
static ring_device_element any_device_element, none_device_element;

/* List of all ring sockets. */
static struct list_head ring_table;
static u_int ring_table_size;

/* Protocol hook */
static struct packet_type prot_hook;

/*
  For each device, pf_ring keeps a list of the number of
  available ring socket slots. So that a caller knows in advance whether
  there are slots available (for rings bound to such device)
  that can potentially host the packet
*/
static struct list_head device_ring_list[MAX_NUM_DEVICES];

/* List of virtual filtering devices */
static struct list_head virtual_filtering_devices_list;
static rwlock_t virtual_filtering_lock = RW_LOCK_UNLOCKED;

/* List of all clusters */
static struct list_head ring_cluster_list;

/* List of all devices on which PF_RING has been registered */
static struct list_head ring_aware_device_list; /* List of ring_device_element */

/* Keep track of number of rings per device (plus any) */
static u_int8_t num_rings_per_device[MAX_NUM_IFIDX] = { 0 };
static u_int8_t num_any_rings = 0;

/* List of all dna (direct nic access) devices */
static struct list_head ring_dna_devices_list;
static u_int dna_devices_list_size = 0;

/* List of all plugins */
static u_int plugin_registration_size = 0;
static struct pfring_plugin_registration *plugin_registration[MAX_PLUGIN_ID] = { NULL };
static u_short max_registered_plugin_id = 0;

/* ********************************** */

/* /proc entry for ring module */
struct proc_dir_entry *ring_proc_dir = NULL, *ring_proc_dev_dir = NULL;
struct proc_dir_entry *ring_proc = NULL;
struct proc_dir_entry *ring_proc_plugins_info = NULL;

static int ring_proc_get_info(char *, char **, off_t, int, int *, void *);
static int ring_proc_get_plugin_info(char *, char **, off_t, int, int *,
				     void *);
static void ring_proc_add(struct pf_ring_socket *pfr);
static void ring_proc_remove(struct pf_ring_socket *pfr);
static void ring_proc_init(void);
static void ring_proc_term(void);

static int reflect_packet(struct sk_buff *skb,
			  struct pf_ring_socket *pfr,
			  struct net_device *reflector_dev,
			  int displ, rule_action_behaviour behaviour);

/* ********************************** */

#if 0

static rwlock_t ring_mgmt_lock;

inline void init_ring_readers(void)      { ring_mgmt_lock = RW_LOCK_UNLOCKED; }
inline void ring_write_lock(void)        { write_lock_bh(&ring_mgmt_lock);    }
inline void ring_write_unlock(void)      { write_unlock_bh(&ring_mgmt_lock);  }
inline void ring_read_lock(void)         { read_lock_bh(&ring_mgmt_lock);     }
inline void ring_read_unlock(void)       { read_unlock_bh(&ring_mgmt_lock);   }

#else

static atomic_t num_ring_readers, ring_stop;

/* Do NOT call schedule() as this might cause crash when exiting */

inline void init_ring_readers(void) {
  atomic_set(&num_ring_readers, 0);
  atomic_set(&ring_stop, 0);
}

inline void ring_write_lock(void) {
  atomic_set(&ring_stop, 1);

  while(atomic_read(&num_ring_readers) > 0) { /* schedule() */; }
}

inline void ring_write_unlock(void) {
  atomic_set(&ring_stop, 0);
}

inline void ring_read_lock(void) {
  while(atomic_read(&ring_stop) == 1) { /* schedule() */; }
  atomic_inc(&num_ring_readers);
}

inline void ring_read_unlock(void) {
  atomic_dec(&num_ring_readers);
}

#endif

/* ********************************** */

/*
  Caveat
  [http://lists.metaprl.org/pipermail/cs134-labs/2002-October/000025.html]

  GFP_ATOMIC means roughly "make the allocation operation atomic".  This
  means that the kernel will try to find the memory using a pile of free
  memory set aside for urgent allocation.  If that pile doesn't have
  enough free pages, the operation will fail.  This flag is useful for
  allocation within interrupt handlers.

  GFP_KERNEL will try a little harder to find memory.  There's a
  possibility that the call to kmalloc() will sleep while the kernel is
  trying to find memory (thus making it unsuitable for interrupt
  handlers).  It's much more rare for an allocation with GFP_KERNEL to
  fail than with GFP_ATOMIC.

  In all cases, kmalloc() should only be used allocating small amounts of
  memory (a few kb).  vmalloc() is better for larger amounts.

  Also note that in lab 1 and lab 2, it would have been arguably better to
  use GFP_KERNEL instead of GFP_ATOMIC.  GFP_ATOMIC should be saved for
  those instances in which a sleep would be totally unacceptable.
*/
/* ********************************** */

/* Forward */
static struct proto_ops ring_ops;

#if(LINUX_VERSION_CODE > KERNEL_VERSION(2,6,11))
static struct proto ring_proto;
#endif

static int skb_ring_handler(struct sk_buff *skb, u_char recv_packet,
			    u_char real_skb,
			    u_int8_t channel_id, u_int8_t num_rx_channels);
static int buffer_ring_handler(struct net_device *dev, char *data, int len);
static int remove_from_cluster(struct sock *sock, struct pf_ring_socket *pfr);
static int ring_map_dna_device(struct pf_ring_socket *pfr,
			       dna_device_mapping * mapping);

/* Extern */
extern
#if(LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,23))
struct sk_buff *
#else
int
#endif
ip_defrag(struct sk_buff *skb, u32 user);

/* ********************************** */

/* Defaults */
static unsigned int min_num_slots = 4096;
static unsigned int enable_tx_capture = 1;
static unsigned int enable_ip_defrag = 0;
static unsigned int enable_debug = 0;
static unsigned int transparent_mode = standard_linux_path;
static u_int32_t ring_id_serial = 0;


#if defined(RHEL_RELEASE_CODE)
#if(RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(4,8))
#define REDHAT_PATCHED_KERNEL
#endif
#endif

#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)) || defined(REDHAT_PATCHED_KERNEL)
module_param(min_num_slots, uint, 0644);
module_param(transparent_mode, uint, 0644);
module_param(enable_debug, uint, 0644);
module_param(enable_tx_capture, uint, 0644);
module_param(enable_ip_defrag, uint, 0644);
#else
MODULE_PARM(min_num_slots, "i");
MODULE_PARM(transparent_mode, "i");
MODULE_PARM(enable_debug, "i");
MODULE_PARM(enable_tx_capture, "i");
MODULE_PARM(enable_ip_defrag, "i");
#endif

MODULE_PARM_DESC(min_num_slots, "Min number of ring slots");
MODULE_PARM_DESC(transparent_mode,
		 "0=standard Linux, 1=direct2pfring+transparent, 2=direct2pfring+non transparent"
		 "For 1 and 2 you need to use a PF_RING aware driver");
MODULE_PARM_DESC(enable_debug, "Set to 1 to enable PF_RING debug tracing into the syslog");
MODULE_PARM_DESC(enable_tx_capture, "Set to 1 to capture outgoing packets");
MODULE_PARM_DESC(enable_ip_defrag,
		 "Set to 1 to enable IP defragmentation"
		 "(only rx traffic is defragmentead)");

/* ********************************** */

#define MIN_QUEUED_PKTS      64
#define MAX_QUEUE_LOOPS      64

#define ring_sk_datatype(__sk) ((struct pf_ring_socket *)__sk)
#define ring_sk(__sk) ((__sk)->sk_protinfo)

#define _rdtsc() ({ uint64_t x; asm volatile("rdtsc" : "=A" (x)); x; })

/* ***************** Legacy code ************************ */

#if defined(RHEL_MAJOR) && (RHEL_MAJOR == 5) && (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18))
/* Redhat backports these functions to 2.6.18 so do nothing */
#else

#if(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23))
static inline void skb_reset_network_header(struct sk_buff *skb) {
  /* skb->network_header = skb->data - skb->head; */
}

static inline void skb_reset_transport_header(struct sk_buff *skb) {
  /* skb->transport_header = skb->data - skb->head; */
}

static inline void skb_set_network_header(struct sk_buff *skb, const int offset) {
  skb_reset_network_header(skb);
  /* skb->network_header += offset; */
}

#endif /* KERNEL_VERSION */
#endif /* RH_MAJOR */

#if(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,16)) || (defined(RHEL_MAJOR) && (RHEL_MAJOR == 5) && (RHEL_MINOR < 2))
static inline struct iphdr *ip_hdr(const struct sk_buff *skb)
{
  return(struct iphdr *)skb->nh.iph;
}

#if(!defined(REDHAT_PATCHED_KERNEL)) || ((RHEL_MAJOR == 5) && (RHEL_MINOR < 2))
static inline void skb_set_network_header(struct sk_buff *skb, const int offset)
{
  skb->nh.iph = (struct iphdr *)skb->data + offset;
}

static inline void skb_reset_network_header(struct sk_buff *skb)
{
  ;
}

static inline void skb_reset_transport_header(struct sk_buff *skb)
{
  ;
}
#endif
#endif

/* ************************************************** */

static inline char* get_slot(struct pf_ring_socket *pfr, u_int32_t off) { return(&(pfr->ring_slots[off])); }

/* ********************************** */

static inline int get_next_slot_offset(struct pf_ring_socket *pfr, u_int32_t off, u_int32_t *real_off)
{
  struct pfring_pkthdr *hdr;
  u_int32_t real_slot_size;

  // smp_rmb();

  hdr = (struct pfring_pkthdr*)get_slot(pfr, off);
  real_slot_size = pfr->slot_header_len + hdr->extended_hdr.parsed_header_len + hdr->caplen;

  if((off + real_slot_size + pfr->slots_info->slot_len) > (pfr->slots_info->tot_mem - sizeof(FlowSlotInfo))) {
    *real_off = pfr->slots_info->tot_mem - sizeof(FlowSlotInfo) - off;
    return 0;
  }

  *real_off = real_slot_size;
  return (off + real_slot_size);
}

/* ********************************** */

static inline u_int32_t num_queued_pkts(struct pf_ring_socket *pfr)
{
  // smp_rmb();

  if(pfr->ring_slots != NULL) {
    u_int32_t tot_insert = pfr->slots_info->tot_insert, tot_read = pfr->slots_info->tot_read;

    if(tot_insert >= tot_read) {
      return(tot_insert - tot_read);
    } else {
      return(((u_int32_t) - 1) + tot_insert - tot_read);
    }

    if(enable_debug) {
      printk("[PF_RING] -> [tot_insert=%d][tot_read=%d]\n",
	     tot_insert, tot_read);
    }
  } else
    return(0);
}

/* ************************************* */

inline u_int get_num_ring_free_slots(struct pf_ring_socket * pfr)
{
  u_int32_t nqpkts = num_queued_pkts(pfr);

  if(nqpkts < (pfr->slots_info->min_num_slots))
    return(pfr->slots_info->min_num_slots - nqpkts);
  else
    return(0);
}

/* ********************************** */

static inline int check_and_init_free_slot(struct pf_ring_socket *pfr, int off)
{
  // smp_rmb();

  if(pfr->slots_info->insert_off == pfr->slots_info->remove_off) {
    /*
      Both insert and remove offset are set on the same slot.
      We need to find out whether the memory is full or empty
    */

    if(num_queued_pkts(pfr) >= min_num_slots)
      return(0); /* Memory is full */
  } else {
    /* There are packets in the ring. We have to check whether we have enough to accommodate a new packet */

    if(pfr->slots_info->insert_off < pfr->slots_info->remove_off) {
      if((pfr->slots_info->remove_off - pfr->slots_info->insert_off) < pfr->slots_info->slot_len)
	return(0);
    } else {
      /* We have enough room for the incoming packet as after we insert a packet, the insert_off
	 offset is wrapped to the beginning in case the space remaining is less than slot_len
	 (i.e. the memory needed to accommodate a packet)
      */
    }
  }

  return 1;
}

/* ********************************** */

#define IP_DEFRAG_RING 1234

/* Returns new sk_buff, or NULL  */
static struct sk_buff *ring_gather_frags(struct sk_buff *skb)
{
#if(LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,23))
  skb = ip_defrag(skb, IP_DEFRAG_RING);

  if(skb)
    ip_send_check(ip_hdr(skb));
#else
  if(ip_defrag(skb, IP_DEFRAG_RING))
    skb = NULL;
  else
    ip_send_check(ip_hdr(skb));
#endif

  return(skb);
}

/* ********************************** */

static void ring_sock_destruct(struct sock *sk)
{
  struct pf_ring_socket *pfr;

  skb_queue_purge(&sk->sk_receive_queue);

  if(!sock_flag(sk, SOCK_DEAD)) {
    if(enable_debug) {
      printk("[PF_RING] Attempt to release alive ring socket: %p\n", sk);
    }
    return;
  }

  pfr = ring_sk(sk);

  if(pfr)
    kfree(pfr);
}

/* ********************************** */

static void ring_proc_add(struct pf_ring_socket *pfr)
{
  if((ring_proc_dir != NULL)
     && (pfr->sock_proc_name[0] == '\0')) {
    snprintf(pfr->sock_proc_name, sizeof(pfr->sock_proc_name),
	     "%d-%s.%d", pfr->ring_pid,
	     pfr->ring_netdev->dev->name, pfr->ring_id);

    create_proc_read_entry(pfr->sock_proc_name, 0 /* read-only */,
			   ring_proc_dir,
			   ring_proc_get_info, pfr);

    printk("[PF_RING] Added /proc/net/pf_ring/%s\n",
	   pfr->sock_proc_name);
  }
}

/* ********************************** */

static void ring_proc_remove(struct pf_ring_socket *pfr)
{
  if((ring_proc_dir != NULL)
     && (pfr->sock_proc_name[0] != '\0')) {
    printk("[PF_RING] Removing /proc/net/pf_ring/%s\n", pfr->sock_proc_name);

    remove_proc_entry(pfr->sock_proc_name, ring_proc_dir);

    if(enable_debug)
      printk("[PF_RING] Removed /proc/net/pf_ring/%s\n", pfr->sock_proc_name);

    pfr->sock_proc_name[0] = '\0';
  }
}

/* ********************************** */

static int ring_proc_dev_get_info(char *buf, char **start, off_t offset,
				  int len, int *unused, void *data)
{
  int rlen = 0;

  if(data != NULL) {
    ring_device_element *dev_ptr = (ring_device_element*)data;
    struct net_device *dev = dev_ptr->dev;
    char dev_buf[16] = { 0 }, *dev_family = "???";

    switch(dev_ptr->device_type) {
    case standard_nic_family: dev_family = "Standard NIC"; break;
    case intel_82599_family:  dev_family = "Intel 82599"; break;
    case silicom_redirector_family: dev_family = "Silicom Redirector"; break;
    }

    rlen =  sprintf(buf,      "Name:              %s\n", dev->name);
    rlen += sprintf(buf+rlen, "Index:             %d\n", dev->ifindex);

    switch(dev->type) {
    case 1:   strcpy(dev_buf, "Ethernet"); break;
    case 772: strcpy(dev_buf, "Loopback"); break;
    default: sprintf(dev_buf, "%d", dev->type); break;
    }

    rlen += sprintf(buf+rlen, "Type:              %s\n", dev_buf);
    rlen += sprintf(buf+rlen, "Family:            %s\n", dev_family);

    if(dev->ifindex < MAX_NUM_IFIDX)
      rlen += sprintf(buf+rlen, "# bound sockets:   %d\n",
		      num_rings_per_device[dev->ifindex]);

#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31))
    rlen += sprintf(buf+rlen, "Max # TX Queues:   %d\n", dev->num_tx_queues);
    rlen += sprintf(buf+rlen, "# Used TX Queues:  %d\n", dev->real_num_tx_queues);
#endif
  }

  return rlen;
}

/* **************** 82599 ****************** */

static int i82599_generic_handler(struct pf_ring_socket *pfr,
				  hw_filtering_rule *rule, hw_filtering_rule_command request) {
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31))
  struct net_device *dev = pfr->ring_netdev->dev;
  struct ethtool_eeprom eeprom; /* Used to to the magic [MAGIC_HW_FILTERING_RULE_REQUEST] */

  if(dev == NULL) return(-1);

  if((dev->ethtool_ops == NULL) || (dev->ethtool_ops->set_eeprom == NULL)) return(-1);

  if(enable_debug) printk("[PF_RING] hw_filtering_rule[%s][request=%d][%p]\n",
		   dev->name, request, dev->ethtool_ops->set_eeprom);

  eeprom.len = 1 /* add/remove (no check) */,
    eeprom.magic = MAGIC_HW_FILTERING_RULE_REQUEST, eeprom.offset = request;

  return(dev->ethtool_ops->set_eeprom(dev, &eeprom, (u8*)rule));
#else
  return(-1);
#endif
}

/* ************************************* */

static int handle_hw_filtering_rule(struct pf_ring_socket *pfr,
				    hw_filtering_rule *rule,
				    hw_filtering_rule_command command) {

  printk("[PF_RING] --> handle_hw_filtering_rule(command=%d)\n", command);

  switch(rule->rule_family_type) {
  case intel_82599_five_tuple_rule:
    if(pfr->ring_netdev->hw_filters.filter_handlers.five_tuple_handler == NULL)
      return(-EINVAL);
    else
      return(i82599_generic_handler(pfr, rule, command));
    break;

  case intel_82599_perfect_filter_rule:
    if(pfr->ring_netdev->hw_filters.filter_handlers.perfect_filter_handler == NULL)
      return(-EINVAL);
    else
      return(i82599_generic_handler(pfr, rule, command));
    break;

  case silicom_redirector_rule:
    if(pfr->ring_netdev->hw_filters.filter_handlers.redirector_rule_handler == NULL)
      return(-EINVAL);
    else
      return(pfr->ring_netdev->hw_filters.filter_handlers.redirector_rule_handler(pfr, rule, command));
    break;
  }

  return(-EINVAL);
}

/* ***************************************** */

#ifdef ENABLE_PROC_WRITE_RULE
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31))
static int ring_proc_dev_rule_read(char *buf, char **start, off_t offset,
				   int len, int *unused, void *data)
{
  int rlen = 0;

  if(data != NULL) {
    ring_device_element *dev_ptr = (ring_device_element*)data;
    struct net_device *dev = dev_ptr->dev;

    rlen =  sprintf(buf,      "Name:              %s\n", dev->name);
    rlen += sprintf(buf+rlen, "# Filters:         %d\n", dev_ptr->hw_filters.num_filters);
    rlen += sprintf(buf+rlen, "\nFiltering Rules:\n"
		    "[perfect rule]  +|-(rule_id,queue_id,vlan,tcp|udp,src_ip/mask,src_port,dst_ip/mask,dst_port)\n"
		    "Example:\t+(1,-1,0,tcp,192.168.0.10/32,25,10.6.0.0/16,0) (queue_id = -1 => drop)\n\n"
		    "[5 tuple rule]  +|-(rule_id,queue_id,tcp|udp,src_ip,src_port,dst_ip,dst_port)\n"
		    "Example:\t+(1,-1,tcp,192.168.0.10,25,0.0.0.0,0)\n\n"
		    "Note:\n\t- queue_id = -1 => drop\n\t- 0 = ignore value\n");
  }

  return rlen;
}
#endif

/* ********************************** */

#ifdef ENABLE_PROC_WRITE_RULE
static void init_intel_82599_five_tuple_filter_hw_rule(u_int8_t queue_id, u_int8_t proto,
						       u_int32_t s_addr, u_int32_t d_addr,
						       u_int16_t s_port, u_int16_t d_port,
						       intel_82599_five_tuple_filter_hw_rule *rule) {

  /* printk("init_intel_82599_five_tuple_filter_hw_rule()\n"); */

  memset(rule, 0, sizeof(intel_82599_five_tuple_filter_hw_rule));

  rule->queue_id = queue_id, rule->proto = proto;
  rule->s_addr = s_addr, rule->d_addr = d_addr;
  rule->s_port = s_port, rule->d_port = d_port;
}

/* ********************************** */

static void init_intel_82599_perfect_filter_hw_rule(u_int8_t queue_id,
						    u_int8_t proto, u_int16_t vlan,
						    u_int32_t s_addr, u_int8_t s_mask,
						    u_int32_t d_addr, u_int8_t d_mask,
						    u_int16_t s_port, u_int16_t d_port,
						    intel_82599_perfect_filter_hw_rule *rule) {
  u_int32_t netmask;

  /* printk("init_intel_82599_perfect_filter_hw_rule()\n"); */

  memset(rule, 0, sizeof(intel_82599_perfect_filter_hw_rule));

  rule->queue_id = queue_id, rule->vlan_id = vlan, rule->proto = proto;

  rule->s_addr = s_addr;
  if(s_mask == 32) netmask = 0xFFFFFFFF; else netmask = ~(0xFFFFFFFF >> s_mask);
  rule->s_addr &= netmask;

  rule->d_addr = d_addr;
  if(d_mask == 32) netmask = 0xFFFFFFFF; else netmask = ~(0xFFFFFFFF >> d_mask);
  rule->d_addr &= netmask;

  rule->s_port = s_port, rule->d_port = d_port;
}

#endif /* ENABLE_PROC_WRITE_RULE */

/* ********************************** */

#ifdef ENABLE_PROC_WRITE_RULE
static int ring_proc_dev_rule_write(struct file *file,
				    const char __user *buffer,
				    unsigned long count, void *data)
{
  char buf[128], add, proto[4] = { 0 };
  ring_device_element *dev_ptr = (ring_device_element*)data;
  int num, queue_id, vlan, rc, rule_id, protocol;
  int s_a, s_b, s_c, s_d, s_mask, s_port;
  int d_a, d_b, d_c, d_d, d_mask, d_port;
  hw_filtering_rule_request rule;
  u_int8_t found = 0;
  int debug = 0;

  if(data == NULL) return(0);

  if(count > (sizeof(buf)-1))             count = sizeof(buf) - 1;
  if(copy_from_user(buf, buffer, count))  return(-EFAULT);
  buf[sizeof(buf)-1] = '\0', buf[count] = '\0';

  if(enable_debug) printk("[PF_RING] ring_proc_dev_rule_write(%s)\n", buf);

  num = sscanf(buf, "%c(%d,%d,%d,%c%c%c,%d.%d.%d.%d/%d,%d,%d.%d.%d.%d/%d,%d)",
	       &add, &rule_id, &queue_id, &vlan,
	       &proto[0], &proto[1], &proto[2],
	       &s_a, &s_b, &s_c, &s_d, &s_mask, &s_port,
	       &d_a, &d_b, &d_c, &d_d, &d_mask, &d_port);

  if(enable_debug)
    printk("[PF_RING] ring_proc_dev_rule_write(%s): num=%d (1)\n", buf, num);

  if(num == 19) {
    if(proto[0] == 't')
      protocol = 6; /* TCP */
    else /* if(proto[0] == 'u') */
      protocol = 17; /* UDP */

    rule.rule.rule_id = rule_id;
    init_intel_82599_perfect_filter_hw_rule(queue_id, protocol, vlan,
					    ((s_a & 0xff) << 24) + ((s_b & 0xff) << 16) + ((s_c & 0xff) << 8) + (s_d & 0xff), s_mask,
					    ((d_a & 0xff) << 24) + ((d_b & 0xff) << 16) + ((d_c & 0xff) << 8) + (d_d & 0xff), d_mask,
					    s_port, d_port, &rule.rule.rule_family.perfect_rule);
    rule.rule.rule_family_type = intel_82599_perfect_filter_rule;
    found = 1;
  }

  if(!found) {
    num = sscanf(buf, "%c(%d,%d,%c%c%c,%d.%d.%d.%d,%d,%d.%d.%d.%d,%d)",
		 &add, &rule_id, &queue_id,
		 &proto[0], &proto[1], &proto[2],
		 &s_a, &s_b, &s_c, &s_d, &s_port,
		 &d_a, &d_b, &d_c, &d_d, &d_port);

    if(enable_debug)
      printk("[PF_RING] ring_proc_dev_rule_write(%s): num=%d (2)\n", buf, num);

    if(num == 16) {
      if(proto[0] == 't')
	protocol = 6; /* TCP */
      else if(proto[0] == 'u')
	protocol = 17; /* UDP */
      else
	protocol = 0; /* any */

      rule.rule.rule_id = rule_id;
      init_intel_82599_five_tuple_filter_hw_rule(queue_id, protocol,
						 ((s_a & 0xff) << 24) + ((s_b & 0xff) << 16) + ((s_c & 0xff) << 8) + (s_d & 0xff),
						 ((d_a & 0xff) << 24) + ((d_b & 0xff) << 16) + ((d_c & 0xff) << 8) + (d_d & 0xff),
						 s_port, d_port, &rule.rule.rule_family.five_tuple_rule);
      rule.rule.rule_family_type = intel_82599_five_tuple_rule;
      found = 1;
    }
  }

  if(!found)
    return(-1);

  rule.command = (add == '+') ? add_hw_rule : remove_hw_rule;
  rc = handle_hw_filtering_rule(dev_ptr->dev, &rule);

  if(rc != -1) {
    /* Rule programmed successfully */

    if(add == '+')
      dev_ptr->hw_filters.num_filters++, pfr->num_hw_filtering_rules++;
    else {
      if(dev_ptr->hw_filters.num_filters > 0)
	dev_ptr->hw_filters.num_filters--;

      pfr->num_hw_filtering_rules--;
    }
  }

  return((int)count);
}
#endif

#endif

/* ********************************** */

static int ring_proc_get_info(char *buf, char **start, off_t offset,
			      int len, int *unused, void *data)
{
  int rlen = 0;
  struct pf_ring_socket *pfr;
  FlowSlotInfo *fsi;

  if(data == NULL) {
    /* /proc/net/pf_ring/info */
    rlen = sprintf(buf, "PF_RING Version     : %s ($Revision: %s$)\n", RING_VERSION, SVN_REV);
    rlen += sprintf(buf + rlen, "Ring slots          : %d\n", min_num_slots);
    rlen += sprintf(buf + rlen, "Slot version        : %d\n", RING_FLOWSLOT_VERSION);
    rlen += sprintf(buf + rlen, "Capture TX          : %s\n", enable_tx_capture ? "Yes [RX+TX]" : "No [RX only]");
    rlen += sprintf(buf + rlen, "IP Defragment       : %s\n", enable_ip_defrag ? "Yes" : "No");
    rlen += sprintf(buf + rlen, "Transparent mode    : %s\n",
		    (transparent_mode == standard_linux_path ? "Yes (mode 0)" :
		     (transparent_mode == driver2pf_ring_transparent ? "Yes (mode 1)" : "No (mode 2)")));
    rlen += sprintf(buf + rlen, "Total rings         : %d\n", ring_table_size);
    rlen += sprintf(buf + rlen, "Total plugins       : %d\n", plugin_registration_size);
  } else {
    /* detailed statistics about a PF_RING */
    pfr = (struct pf_ring_socket *)data;

    if(data) {
      fsi = pfr->slots_info;

      if(fsi) {
	rlen = sprintf(buf,         "Bound Device       : %s\n", pfr->ring_netdev->dev->name);
	rlen += sprintf(buf + rlen, "Slot Version       : %d [%s]\n", fsi->version, RING_VERSION);
	rlen += sprintf(buf + rlen, "Active             : %d\n", pfr->ring_active);
	rlen += sprintf(buf + rlen, "Sampling Rate      : %d\n", pfr->sample_rate);
	rlen += sprintf(buf + rlen, "Appl. Name         : %s\n", pfr->appl_name ? pfr->appl_name : "<unknown>");
	rlen += sprintf(buf + rlen, "IP Defragment      : %s\n", enable_ip_defrag ? "Yes" : "No");
	rlen += sprintf(buf + rlen, "BPF Filtering      : %s\n", pfr->bpfFilter ? "Enabled" : "Disabled");
	rlen += sprintf(buf + rlen, "# Sw Filt. Rules   : %d\n", pfr->num_sw_filtering_rules);
	rlen += sprintf(buf + rlen, "# Hw Filt. Rules   : %d\n", pfr->num_hw_filtering_rules);
	rlen += sprintf(buf + rlen, "Cluster Id         : %d\n", pfr->cluster_id);
	rlen += sprintf(buf + rlen, "Channel Id         : %d\n", pfr->channel_id);
	rlen += sprintf(buf + rlen, "Min Num Slots      : %d\n", fsi->min_num_slots);
	rlen += sprintf(buf + rlen, "Poll Pkt Watermark : %d\n", pfr->poll_num_pkts_watermark);
	rlen += sprintf(buf + rlen, "Bucket Len         : %d\n", fsi->data_len);
	rlen += sprintf(buf + rlen, "Slot Len           : %d [bucket+header]\n", fsi->slot_len);
	rlen += sprintf(buf + rlen, "Tot Memory         : %d\n", fsi->tot_mem);
	rlen += sprintf(buf + rlen, "Tot Packets        : %lu\n", (unsigned long)fsi->tot_pkts);
	rlen += sprintf(buf + rlen, "Tot Pkt Lost       : %lu\n", (unsigned long)fsi->tot_lost);
	rlen += sprintf(buf + rlen, "Tot Insert         : %lu\n", (unsigned long)fsi->tot_insert);
	rlen += sprintf(buf + rlen, "Tot Read           : %lu\n", (unsigned long)fsi->tot_read);
	rlen += sprintf(buf + rlen, "Insert Offset      : %lu\n", (unsigned long)fsi->insert_off);
	rlen += sprintf(buf + rlen, "Remove Offset      : %lu\n", (unsigned long)fsi->remove_off);
	rlen += sprintf(buf + rlen, "Tot Fwd Ok         : %lu\n", (unsigned long)fsi->tot_fwd_ok);
	rlen += sprintf(buf + rlen, "Tot Fwd Errors     : %lu\n", (unsigned long)fsi->tot_fwd_notok);
	rlen += sprintf(buf + rlen, "Num Free Slots     : %u\n",  get_num_ring_free_slots(pfr));
      } else {
	rlen = sprintf(buf, "WARNING ring not active (fsi == NULL)\n");
      }
    } else
      rlen = sprintf(buf, "WARNING data == NULL\n");
  }

  return rlen;
}

/* ********************************** */

static int ring_proc_get_plugin_info(char *buf, char **start, off_t offset,
				     int len, int *unused, void *data)
{
  int rlen = 0, i = 0;
  struct pfring_plugin_registration *tmp = NULL;

  /* FIXME: I should now the number of plugins registered */
  if(!plugin_registration_size)
    return rlen;

  /* plugins_info */

  rlen += sprintf(buf + rlen, "ID\tPlugin\n");

  for(i = 0; i < MAX_PLUGIN_ID; i++) {
    tmp = plugin_registration[i];
    if(tmp) {
      rlen += sprintf(buf + rlen, "%d\t%s [%s]\n",
		      tmp->plugin_id, tmp->name,
		      tmp->description);
    }
  }

  return rlen;
}

/* ********************************** */

static void ring_proc_init(void)
{
  ring_proc_dir = proc_mkdir("pf_ring",
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24))
			     init_net.
#endif
			     proc_net);

  if(ring_proc_dir) {
#if(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30))
    ring_proc_dir->owner = THIS_MODULE;
#endif

    ring_proc_dev_dir = proc_mkdir(PROC_DEV, ring_proc_dir);

    ring_proc = create_proc_read_entry(PROC_INFO, 0 /* read-only */,
				       ring_proc_dir,
				       ring_proc_get_info, NULL);
    ring_proc_plugins_info =
      create_proc_read_entry(PROC_PLUGINS_INFO, 0 /* read-only */,
			     ring_proc_dir,
			     ring_proc_get_plugin_info, NULL);
    if(!ring_proc || !ring_proc_plugins_info)
      printk("[PF_RING] unable to register proc file\n");
    else {
#if(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30))
      ring_proc->owner = THIS_MODULE;
      ring_proc_plugins_info->owner = THIS_MODULE;
#endif
      printk("[PF_RING] registered /proc/net/pf_ring/\n");
    }
  } else
    printk("[PF_RING] unable to create /proc/net/pf_ring\n");
}

/* ********************************** */

static void ring_proc_term(void)
{
  if(ring_proc != NULL) {
    remove_proc_entry(PROC_INFO, ring_proc_dir);
    printk("[PF_RING] removed /proc/net/pf_ring/%s\n", PROC_INFO);

    remove_proc_entry(PROC_PLUGINS_INFO, ring_proc_dir);
    printk("[PF_RING] removed /proc/net/pf_ring/%s\n",
	   PROC_PLUGINS_INFO);

    remove_proc_entry(PROC_DEV, ring_proc_dir);

    if(ring_proc_dir != NULL) {
      remove_proc_entry("pf_ring",
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24))
			init_net.
#endif
			proc_net);
      printk("[PF_RING] deregistered /proc/net/pf_ring\n");
    }
  }
}

/* ********************************** */

/*
 * Allocate ring memory used later on for
 * mapping it to userland
 */
static int ring_alloc_mem(struct sock *sk)
{
  u_int the_slot_len, num_pages;
  u_int32_t tot_mem;
  struct pf_ring_socket *pfr = ring_sk(sk);

  /* Check if the memory has been already allocated */
  if(pfr->ring_memory != NULL) return(0);

  if(enable_debug)
    printk("[PF_RING] ring_alloc_mem(bucket_len=%d)\n", pfr->bucket_len);

  /* **********************************************

   * *************************************
   * *                                   *
   * *        FlowSlotInfo               *
   * *                                   *
   * ************************************* <-+
   * *        FlowSlot                   *   |
   * *************************************   |
   * *        FlowSlot                   *   |
   * *************************************   +- >= min_num_slots
   * *        FlowSlot                   *   |
   * *************************************   |
   * *        FlowSlot                   *   |
   * ************************************* <-+
   *
   * ********************************************** */

  pfr->slot_header_len = sizeof(struct pfring_pkthdr);
  the_slot_len = pfr->slot_header_len + pfr->bucket_len;

  tot_mem = PAGE_ALIGN(sizeof(FlowSlotInfo) + min_num_slots * the_slot_len);

  /* Alignment necessary on ARM platforms */
  num_pages = tot_mem / PAGE_SIZE;
  num_pages += (num_pages + (SHMLBA-1)) % SHMLBA;
  tot_mem = num_pages*PAGE_SIZE;

  /* rounding size to the next power of 2 (needed by vPFRing) */
  tot_mem--;
  tot_mem |= tot_mem >> 1;
  tot_mem |= tot_mem >> 2;
  tot_mem |= tot_mem >> 4;
  tot_mem |= tot_mem >> 8;
  tot_mem |= tot_mem >> 16;
  tot_mem++;

  pfr->ring_memory = vmalloc_user(tot_mem);

  if(pfr->ring_memory != NULL) {
    if(enable_debug)
      printk("[PF_RING] successfully allocated %lu bytes at 0x%08lx\n",
	     (unsigned long)tot_mem, (unsigned long)pfr->ring_memory);

    /* Memory is already zeroed */
    /* memset(pfr->ring_memory, 0, tot_mem); */
  } else {
    printk("[PF_RING] ERROR: not enough memory for ring\n");
    return(-1);
  }

  pfr->slots_info = (FlowSlotInfo *) pfr->ring_memory;
  pfr->ring_slots = (char *)(pfr->ring_memory + sizeof(FlowSlotInfo));

  pfr->slots_info->version = RING_FLOWSLOT_VERSION;
  pfr->slots_info->slot_len = the_slot_len;
  pfr->slots_info->data_len = pfr->bucket_len;
  pfr->slots_info->min_num_slots = (tot_mem - sizeof(FlowSlotInfo)) / the_slot_len;
  pfr->slots_info->tot_mem = tot_mem;
  pfr->slots_info->sample_rate = 1;

  if(enable_debug)
    printk("[PF_RING] allocated %d slots [slot_len=%d][tot_mem=%u]\n",
	   pfr->slots_info->min_num_slots, pfr->slots_info->slot_len,
	   pfr->slots_info->tot_mem);

  pfr->insert_page_id = 1, pfr->insert_slot_id = 0;
  pfr->sw_filtering_rules_default_accept_policy = 1;
  pfr->num_sw_filtering_rules = pfr->num_hw_filtering_rules = 0;

  return(0);
}

/* ********************************** */

/*
 * ring_insert()
 *
 * store the sk in a new element and add it
 * to the head of the list.
 */
static inline void ring_insert(struct sock *sk)
{
  struct ring_element *next;
  struct pf_ring_socket *pfr;

  if(enable_debug)
    printk("[PF_RING] ring_insert()\n");

  next = kmalloc(sizeof(struct ring_element), GFP_ATOMIC);
  if(next != NULL) {
    next->sk = sk;
    ring_write_lock();
    list_add(&next->list, &ring_table);
    ring_write_unlock();
  } else {
    if(net_ratelimit())
      printk("[PF_RING] net_ratelimit() failure\n");
  }

  ring_table_size++;

  pfr = (struct pf_ring_socket *)ring_sk(sk);
  pfr->ring_pid = current->pid;
}

/* ********************************** */

/*
 * ring_remove()
 *
 * For each of the elements in the list:
 *  - check if this is the element we want to delete
 *  - if it is, remove it from the list, and free it.
 *
 * stop when we find the one we're looking for(break),
 * or when we reach the end of the list.
 */
static inline void ring_remove(struct sock *sk)
{
  struct list_head *ptr, *tmp_ptr;
  struct ring_element *entry, *to_delete = NULL;
  struct pf_ring_socket *pfr_to_delete = ring_sk(sk);
  u_int8_t master_found = 0, socket_found = 0;

  if(enable_debug)
    printk("[PF_RING] ring_remove()\n");

  list_for_each_safe(ptr, tmp_ptr, &ring_table) {
    struct pf_ring_socket *pfr;

    entry = list_entry(ptr, struct ring_element, list);
    pfr = ring_sk(entry->sk);

    if(pfr->master_ring == pfr_to_delete) {
      if(enable_debug)
	printk("[PF_RING] Removing master ring\n");

      pfr->master_ring = NULL, master_found = 1;
    } else if(entry->sk == sk) {
      if(enable_debug)
	printk("[PF_RING] Found socket to remove\n");

      list_del(ptr);
      to_delete = entry;
      ring_table_size--, socket_found = 1;
    }

    if(master_found && socket_found) break;
  }

  if(to_delete) kfree(to_delete);

  if(enable_debug)
    printk("[PF_RING] leaving ring_remove()\n");
}

/* ******************************************************* */

static int parse_pkt(struct sk_buff *skb,
		     u_int16_t skb_displ,
		     struct pfring_pkthdr *hdr, u_int8_t reset_all)
{
  struct ethhdr *eh = (struct ethhdr *)(skb->data - skb_displ);
  u_int16_t displ, ip_len;

  if(reset_all)
    memset(&hdr->extended_hdr, 0, sizeof(hdr->extended_hdr));
  else
    memset(&hdr->extended_hdr, 0, sizeof(hdr->extended_hdr)-sizeof(packet_user_detail) /* Preserve user data */);

  /* MAC address */
  memcpy(&hdr->extended_hdr.parsed_pkt.dmac, eh->h_dest, sizeof(eh->h_dest));
  memcpy(&hdr->extended_hdr.parsed_pkt.smac, eh->h_source, sizeof(eh->h_source));

  hdr->extended_hdr.parsed_pkt.eth_type = ntohs(eh->h_proto);
  hdr->extended_hdr.parsed_pkt.offset.eth_offset = -skb_displ;

  if(hdr->extended_hdr.parsed_pkt.eth_type == 0x8100 /* 802.1q (VLAN) */) {
    hdr->extended_hdr.parsed_pkt.offset.vlan_offset =
      hdr->extended_hdr.parsed_pkt.offset.eth_offset + sizeof(struct ethhdr);
    hdr->extended_hdr.parsed_pkt.vlan_id =
      (skb->data[hdr->extended_hdr.parsed_pkt.offset.vlan_offset] & 15) * 256 +
      skb->data[hdr->extended_hdr.parsed_pkt.offset.vlan_offset + 1];
    hdr->extended_hdr.parsed_pkt.eth_type =
      (skb->data[hdr->extended_hdr.parsed_pkt.offset.vlan_offset + 2]) * 256 +
      skb->data[hdr->extended_hdr.parsed_pkt.offset.vlan_offset + 3];
    displ = 4;
  } else {
    displ = 0;
    hdr->extended_hdr.parsed_pkt.vlan_id = 0;	/* Any VLAN */
  }

  if(hdr->extended_hdr.parsed_pkt.eth_type == 0x0800 /* IPv4 */ ) {
    struct iphdr *ip;

    hdr->extended_hdr.parsed_pkt.offset.l3_offset = hdr->extended_hdr.parsed_pkt.offset.eth_offset + displ + sizeof(struct ethhdr);

    ip = (struct iphdr *)(skb->data + hdr->extended_hdr.parsed_pkt.offset.l3_offset);

    hdr->extended_hdr.parsed_pkt.ipv4_src = ntohl(ip->saddr);
    hdr->extended_hdr.parsed_pkt.ipv4_dst = ntohl(ip->daddr);
    hdr->extended_hdr.parsed_pkt.l3_proto = ip->protocol;
    hdr->extended_hdr.parsed_pkt.ipv4_tos = ip->tos;
    hdr->extended_hdr.parsed_pkt.ip_version = 4;
    ip_len  = ip->ihl*4;
  } else if(hdr->extended_hdr.parsed_pkt.eth_type == 0x86DD /* IPv6 */) {
    struct ipv6hdr *ipv6;

    hdr->extended_hdr.parsed_pkt.ip_version = 6;
    ip_len = 40;

    hdr->extended_hdr.parsed_pkt.offset.l3_offset = hdr->extended_hdr.parsed_pkt.offset.eth_offset+displ+sizeof(struct ethhdr);
    ipv6 = (struct ipv6hdr*)(skb->data+hdr->extended_hdr.parsed_pkt.offset.l3_offset);

    /* Values of IPv6 addresses are stored as network byte order */
    hdr->extended_hdr.parsed_pkt.ipv6_src = ipv6->saddr;
    hdr->extended_hdr.parsed_pkt.ipv6_dst = ipv6->daddr;

    hdr->extended_hdr.parsed_pkt.l3_proto = ipv6->nexthdr;
    hdr->extended_hdr.parsed_pkt.ipv6_tos = ipv6->priority; /* IPv6 class of service */

    /*
      RFC2460 4.1  Extension Header Order
      IPv6 header
      Hop-by-Hop Options header
      Destination Options header
      Routing header
      Fragment header
      Authentication header
      Encapsulating Security Payload header
      Destination Options header
      upper-layer header
    */

    while(hdr->extended_hdr.parsed_pkt.l3_proto == NEXTHDR_HOP	||
	  hdr->extended_hdr.parsed_pkt.l3_proto == NEXTHDR_DEST	||
	  hdr->extended_hdr.parsed_pkt.l3_proto == NEXTHDR_ROUTING	||
	  hdr->extended_hdr.parsed_pkt.l3_proto == NEXTHDR_AUTH	||
	  hdr->extended_hdr.parsed_pkt.l3_proto == NEXTHDR_ESP	||
	  hdr->extended_hdr.parsed_pkt.l3_proto == NEXTHDR_FRAGMENT)
      {
	struct ipv6_opt_hdr *ipv6_opt;
	ipv6_opt = (struct ipv6_opt_hdr *)(skb->data+hdr->extended_hdr.parsed_pkt.offset.l3_offset+ip_len);
	ip_len += 8;
	if(hdr->extended_hdr.parsed_pkt.l3_proto == NEXTHDR_AUTH)
	  /*
	    RFC4302 2.2. Payload Length: This 8-bit field specifies the
	    length of AH in 32-bit words (4-byte units), minus "2".
	  */
	  ip_len += ipv6_opt->hdrlen * 4;
	else if(hdr->extended_hdr.parsed_pkt.l3_proto != NEXTHDR_FRAGMENT)
	  ip_len += ipv6_opt->hdrlen;

	hdr->extended_hdr.parsed_pkt.l3_proto = ipv6_opt->nexthdr;
      }
  } else {
    hdr->extended_hdr.parsed_pkt.l3_proto = 0;
    return(0); /* No IP */
  }

  if((hdr->extended_hdr.parsed_pkt.l3_proto == IPPROTO_TCP) || (hdr->extended_hdr.parsed_pkt.l3_proto == IPPROTO_UDP)) {
    hdr->extended_hdr.parsed_pkt.offset.l4_offset = hdr->extended_hdr.parsed_pkt.offset.l3_offset+ip_len;

    if(hdr->extended_hdr.parsed_pkt.l3_proto == IPPROTO_TCP) {
      struct tcphdr *tcp = (struct tcphdr *)(skb->data+hdr->extended_hdr.parsed_pkt.offset.l4_offset);
      hdr->extended_hdr.parsed_pkt.l4_src_port = ntohs(tcp->source), hdr->extended_hdr.parsed_pkt.l4_dst_port = ntohs(tcp->dest);
      hdr->extended_hdr.parsed_pkt.offset.payload_offset = hdr->extended_hdr.parsed_pkt.offset.l4_offset + (tcp->doff * 4);
      hdr->extended_hdr.parsed_pkt.tcp.seq_num = ntohl(tcp->seq), hdr->extended_hdr.parsed_pkt.tcp.ack_num = ntohl(tcp->ack_seq);
      hdr->extended_hdr.parsed_pkt.tcp.flags =
	(tcp->fin * TH_FIN_MULTIPLIER) + (tcp->syn * TH_SYN_MULTIPLIER) +
	(tcp->rst * TH_RST_MULTIPLIER) + (tcp->psh * TH_PUSH_MULTIPLIER) +
	(tcp->ack * TH_ACK_MULTIPLIER) + (tcp->urg * TH_URG_MULTIPLIER);
    } else if(hdr->extended_hdr.parsed_pkt.l3_proto == IPPROTO_UDP) {
      struct udphdr *udp = (struct udphdr *)(skb->data + hdr->extended_hdr.parsed_pkt.offset.l4_offset);
      hdr->extended_hdr.parsed_pkt.l4_src_port = ntohs(udp->source), hdr->extended_hdr.parsed_pkt.l4_dst_port = ntohs(udp->dest);
      hdr->extended_hdr.parsed_pkt.offset.payload_offset = hdr->extended_hdr.parsed_pkt.offset.l4_offset + sizeof(struct udphdr);
    } else
      hdr->extended_hdr.parsed_pkt.offset.payload_offset = hdr->extended_hdr.parsed_pkt.offset.l4_offset;
  } else
    hdr->extended_hdr.parsed_pkt.l4_src_port = hdr->extended_hdr.parsed_pkt.l4_dst_port = 0;

  hdr->extended_hdr.parsed_pkt.offset.eth_offset = skb_displ;

  return(1);	/* IP */
}

/* ********************************** */

inline u_int32_t hash_pkt(u_int16_t vlan_id, u_int8_t proto,
			  ip_addr host_peer_a, ip_addr host_peer_b,
			  u_int16_t port_peer_a, u_int16_t port_peer_b)
{
  return(vlan_id+proto+
	 host_peer_a.v6.s6_addr32[0]+host_peer_a.v6.s6_addr32[1]+
	 host_peer_a.v6.s6_addr32[2]+host_peer_a.v6.s6_addr32[3]+
	 host_peer_b.v6.s6_addr32[0]+host_peer_b.v6.s6_addr32[1]+
	 host_peer_b.v6.s6_addr32[2]+host_peer_b.v6.s6_addr32[3]+
	 port_peer_a+port_peer_b);
}

/* ********************************** */

inline u_int32_t hash_pkt_header(struct pfring_pkthdr * hdr, u_char mask_src,
				 u_char mask_dst)
{
  return(hash_pkt(hdr->extended_hdr.parsed_pkt.vlan_id,
		  hdr->extended_hdr.parsed_pkt.l3_proto,
		  mask_src ? ip_zero : hdr->extended_hdr.parsed_pkt.ip_src,
		  mask_dst ? ip_zero : hdr->extended_hdr.parsed_pkt.ip_dst,
		  mask_src ? 0 : hdr->extended_hdr.parsed_pkt.l4_src_port,
		  mask_dst ? 0 : hdr->extended_hdr.parsed_pkt.l4_dst_port));
}

/* ********************************** */

static int hash_bucket_match(sw_filtering_hash_bucket * hash_bucket,
			     struct pfring_pkthdr *hdr,
			     u_char mask_src, u_char mask_dst)
{
  if(0)
    printk("[PF_RING] hash_bucket_match() (%u,%d,%d.%d.%d.%d:%u,%d.%d.%d.%d:%u) "
	   "(%u,%d,%d.%d.%d.%d:%u,%d.%d.%d.%d:%u)\n",
	   hash_bucket->rule.vlan_id, hash_bucket->rule.proto,
	   ((hash_bucket->rule.host4_peer_a >> 24) & 0xff),
	   ((hash_bucket->rule.host4_peer_a >> 16) & 0xff),
	   ((hash_bucket->rule.host4_peer_a >> 8) & 0xff),
	   ((hash_bucket->rule.host4_peer_a >> 0) & 0xff),
	   hash_bucket->rule.port_peer_a,
	   ((hash_bucket->rule.host4_peer_b >> 24) & 0xff),
	   ((hash_bucket->rule.host4_peer_b >> 16) & 0xff),
	   ((hash_bucket->rule.host4_peer_b >> 8) & 0xff),
	   ((hash_bucket->rule.host4_peer_b >> 0) & 0xff),
	   hash_bucket->rule.port_peer_b,

	   hdr->extended_hdr.parsed_pkt.vlan_id,
	   hdr->extended_hdr.parsed_pkt.l3_proto,
	   ((hdr->extended_hdr.parsed_pkt.ipv4_src >> 24) & 0xff),
	   ((hdr->extended_hdr.parsed_pkt.ipv4_src >> 16) & 0xff),
	   ((hdr->extended_hdr.parsed_pkt.ipv4_src >> 8) & 0xff),
	   ((hdr->extended_hdr.parsed_pkt.ipv4_src >> 0) & 0xff),
	   hdr->extended_hdr.parsed_pkt.l4_src_port,
	   ((hdr->extended_hdr.parsed_pkt.ipv4_dst >> 24) & 0xff),
	   ((hdr->extended_hdr.parsed_pkt.ipv4_dst >> 16) & 0xff),
	   ((hdr->extended_hdr.parsed_pkt.ipv4_dst >> 8) & 0xff),
	   ((hdr->extended_hdr.parsed_pkt.ipv4_dst >> 0) & 0xff),
	   hdr->extended_hdr.parsed_pkt.l4_dst_port);

  /*
    When protocol of host_peer is IPv4, s6_addr32[0] contains IPv4
    address and the value of other elements of s6_addr32 are 0.
  */
  if((hash_bucket->rule.proto == hdr->extended_hdr.parsed_pkt.l3_proto)
     && (hash_bucket->rule.vlan_id == hdr->extended_hdr.parsed_pkt.vlan_id)
     && (((hash_bucket->rule.host4_peer_a == (mask_src ? 0 : hdr->extended_hdr.parsed_pkt.ipv4_src))
	  && (hash_bucket->rule.host4_peer_b == (mask_dst ? 0 : hdr->extended_hdr.parsed_pkt.ipv4_dst))
	  && (hash_bucket->rule.port_peer_a == (mask_src ? 0 : hdr->extended_hdr.parsed_pkt.l4_src_port))
	  && (hash_bucket->rule.port_peer_b == (mask_dst ? 0 : hdr->extended_hdr.parsed_pkt.l4_dst_port)))
	 ||
	 ((hash_bucket->rule.host4_peer_a == (mask_dst ? 0 : hdr->extended_hdr.parsed_pkt.ipv4_dst))
	  && (hash_bucket->rule.host4_peer_b == (mask_src ? 0 : hdr->extended_hdr.parsed_pkt.ipv4_src))
	  && (hash_bucket->rule.port_peer_a == (mask_dst ? 0 : hdr->extended_hdr.parsed_pkt.l4_dst_port))
	  && (hash_bucket->rule.port_peer_b == (mask_src ? 0 : hdr->extended_hdr.parsed_pkt.l4_src_port)))))
    {
      if(hdr->extended_hdr.parsed_pkt.ip_version == 6) {
	if(((memcmp(&hash_bucket->rule.host6_peer_a,
		    (mask_src ? &ip_zero.v6 : &hdr->extended_hdr.parsed_pkt.ipv6_src),
		    sizeof(ip_addr) == 0))
	    && (memcmp(&hash_bucket->rule.host6_peer_b,
		       (mask_dst ? &ip_zero.v6 : &hdr->extended_hdr.parsed_pkt.ipv6_dst),
		       sizeof(ip_addr) == 0)))
	   ||
	   ((memcmp(&hash_bucket->rule.host6_peer_a,
		    (mask_src ? &ip_zero.v6 : &hdr->extended_hdr.parsed_pkt.ipv6_dst),
		    sizeof(ip_addr) == 0))
	    && (memcmp(&hash_bucket->rule.host6_peer_b,
		       (mask_dst ? &ip_zero.v6 : &hdr->extended_hdr.parsed_pkt.ipv6_src),
		       sizeof(ip_addr) == 0)))) {
	  return(1);
	} else {
	  return(0);
	}
      } else {
	return(1);
      }
    } else {
    return(0);
  }
}

/* ********************************** */

inline int hash_bucket_match_rule(sw_filtering_hash_bucket * hash_bucket,
				  hash_filtering_rule * rule)
{
  if(enable_debug)
    printk("[PF_RING] (%u,%d,%d.%d.%d.%d:%u,%d.%d.%d.%d:%u) "
	   "(%u,%d,%d.%d.%d.%d:%u,%d.%d.%d.%d:%u)\n",
	   hash_bucket->rule.vlan_id, hash_bucket->rule.proto,
	   ((hash_bucket->rule.host4_peer_a >> 24) & 0xff),
	   ((hash_bucket->rule.host4_peer_a >> 16) & 0xff),
	   ((hash_bucket->rule.host4_peer_a >> 8) & 0xff),
	   ((hash_bucket->rule.host4_peer_a >> 0) & 0xff),
	   hash_bucket->rule.port_peer_a,
	   ((hash_bucket->rule.host4_peer_b >> 24) & 0xff),
	   ((hash_bucket->rule.host4_peer_b >> 16) & 0xff),
	   ((hash_bucket->rule.host4_peer_b >> 8) & 0xff),
	   ((hash_bucket->rule.host4_peer_b >> 0) & 0xff),
	   hash_bucket->rule.port_peer_b,
	   rule->vlan_id, rule->proto,
	   ((rule->host4_peer_a >> 24) & 0xff),
	   ((rule->host4_peer_a >> 16) & 0xff),
	   ((rule->host4_peer_a >> 8) & 0xff),
	   ((rule->host4_peer_a >> 0) & 0xff),
	   rule->port_peer_a,
	   ((rule->host4_peer_b >> 24) & 0xff),
	   ((rule->host4_peer_b >> 16) & 0xff),
	   ((rule->host4_peer_b >> 8) & 0xff),
	   ((rule->host4_peer_b >> 0) & 0xff), rule->port_peer_b);

  if((hash_bucket->rule.proto == rule->proto)
     && (hash_bucket->rule.vlan_id == rule->vlan_id)
     && (((hash_bucket->rule.host4_peer_a == rule->host4_peer_a)
	  && (hash_bucket->rule.host4_peer_b == rule->host4_peer_b)
	  && (hash_bucket->rule.port_peer_a == rule->port_peer_a)
	  && (hash_bucket->rule.port_peer_b == rule->port_peer_b))
	 || ((hash_bucket->rule.host4_peer_a == rule->host4_peer_b)
	     && (hash_bucket->rule.host4_peer_b == rule->host4_peer_a)
	     && (hash_bucket->rule.port_peer_a == rule->port_peer_b)
	     && (hash_bucket->rule.port_peer_b == rule->port_peer_a)))) {
    hash_bucket->rule.internals.jiffies_last_match = jiffies;
    return(1);
  } else
    return(0);
}

/* ********************************** */

inline int hash_filtering_rule_match(hash_filtering_rule * a,
				     hash_filtering_rule * b)
{
  if(enable_debug)
    printk("[PF_RING] (%u,%d,%d.%d.%d.%d:%u,%d.%d.%d.%d:%u) "
	   "(%u,%d,%d.%d.%d.%d:%u,%d.%d.%d.%d:%u)\n",
	   a->vlan_id, a->proto,
	   ((a->host4_peer_a >> 24) & 0xff),
	   ((a->host4_peer_a >> 16) & 0xff),
	   ((a->host4_peer_a >> 8) & 0xff),
	   ((a->host4_peer_a >> 0) & 0xff),
	   a->port_peer_a,
	   ((a->host4_peer_b >> 24) & 0xff),
	   ((a->host4_peer_b >> 16) & 0xff),
	   ((a->host4_peer_b >> 8) & 0xff),
	   ((a->host4_peer_b >> 0) & 0xff),
	   a->port_peer_b,
	   b->vlan_id, b->proto,
	   ((b->host4_peer_a >> 24) & 0xff),
	   ((b->host4_peer_a >> 16) & 0xff),
	   ((b->host4_peer_a >> 8) & 0xff),
	   ((b->host4_peer_a >> 0) & 0xff),
	   b->port_peer_a,
	   ((b->host4_peer_b >> 24) & 0xff),
	   ((b->host4_peer_b >> 16) & 0xff),
	   ((b->host4_peer_b >> 8) & 0xff),
	   ((b->host4_peer_b >> 0) & 0xff), b->port_peer_b);

  if((a->proto == b->proto)
     && (a->vlan_id == b->vlan_id)
     && (((a->host4_peer_a == b->host4_peer_a)
	  && (a->host4_peer_b == b->host4_peer_b)
	  && (a->port_peer_a == b->port_peer_a)
	  && (a->port_peer_b == b->port_peer_b))
	 || ((a->host4_peer_a == b->host4_peer_b)
	     && (a->host4_peer_b == b->host4_peer_a)
	     && (a->port_peer_a == b->port_peer_b)
	     && (a->port_peer_b == b->port_peer_a)))) {
    return(1);
  } else
    return(0);
}

/* ********************************** */

/* 0 = no match, 1 = match */
static int match_filtering_rule(struct pf_ring_socket *pfr,
				sw_filtering_rule_element * rule,
				struct pfring_pkthdr *hdr,
				struct sk_buff *skb,
				int displ,
				struct parse_buffer *parse_memory_buffer[],
				u_int8_t *free_parse_mem,
				u_int *last_matched_plugin,
				rule_action_behaviour *behaviour)
{
  u_int8_t empty_mac[ETH_ALEN] = { 0 }; /* NULL MAC address */

  if(enable_debug) printk("[PF_RING] match_filtering_rule()\n");

  *behaviour = forward_packet_and_stop_rule_evaluation;	/* Default */

  if((memcmp(rule->rule.core_fields.dmac, empty_mac, ETH_ALEN) != 0)
     && (memcmp(hdr->extended_hdr.parsed_pkt.dmac, rule->rule.core_fields.dmac, ETH_ALEN) != 0))
    return(0);

  if((memcmp(rule->rule.core_fields.smac, empty_mac, ETH_ALEN) != 0)
     && (memcmp(hdr->extended_hdr.parsed_pkt.smac, rule->rule.core_fields.smac, ETH_ALEN) != 0))
    return(0);

  if((rule->rule.core_fields.vlan_id > 0)
     && (hdr->extended_hdr.parsed_pkt.vlan_id != rule->rule.core_fields.vlan_id))
    return(0);

  if((rule->rule.core_fields.proto > 0)
     && (hdr->extended_hdr.parsed_pkt.l3_proto != rule->rule.core_fields.proto))
    return(0);

  /* IPv6 */
  if(hdr->extended_hdr.parsed_pkt.ip_version == 6) {
    if(memcmp(&rule->rule.core_fields.host6_low, &ip_zero, sizeof(struct in6_addr)) > 0) {
      if((memcmp(&hdr->extended_hdr.parsed_pkt.ipv6_src, &rule->rule.core_fields.host6_low, sizeof(struct in6_addr) < 0)
	  || memcmp(&hdr->extended_hdr.parsed_pkt.ipv6_src, &rule->rule.core_fields.host6_high, sizeof(struct in6_addr) > 0))
	 && (memcmp(&hdr->extended_hdr.parsed_pkt.ipv6_dst, &rule->rule.core_fields.host6_low,  sizeof(struct in6_addr) < 0)
	     || memcmp(&hdr->extended_hdr.parsed_pkt.ipv6_dst, &rule->rule.core_fields.host6_high, sizeof(struct in6_addr) > 0)))
	return(0);
    }
  } else if(rule->rule.core_fields.host4_low > 0) {
    if(((hdr->extended_hdr.parsed_pkt.ipv4_src < rule->rule.core_fields.host4_low)
	|| (hdr->extended_hdr.parsed_pkt.ipv4_src > rule->rule.core_fields.host4_high))
       && ((hdr->extended_hdr.parsed_pkt.ipv4_dst < rule->rule.core_fields.host4_low)
	   || (hdr->extended_hdr.parsed_pkt.ipv4_dst > rule->rule.core_fields.host4_high)))
      return(0);
  }

  if(rule->rule.core_fields.port_high > 0) {
    if(((hdr->extended_hdr.parsed_pkt.l4_src_port < rule->rule.core_fields.port_low)
	|| (hdr->extended_hdr.parsed_pkt.l4_src_port > rule->rule.core_fields.port_high))
       && ((hdr->extended_hdr.parsed_pkt.l4_dst_port < rule->rule.core_fields.port_low)
	   || (hdr->extended_hdr.parsed_pkt.l4_dst_port > rule->rule.core_fields.port_high)))
      return(0);
  }

  if(rule->rule.balance_pool > 0) {
    u_int32_t balance_hash =
      hash_pkt_header(hdr, 0, 0) % rule->rule.balance_pool;
    if(balance_hash != rule->rule.balance_id)
      return(0);
  }

#ifdef CONFIG_TEXTSEARCH
  if(rule->pattern[0] != NULL) {
    if(enable_debug)
      printk("[PF_RING] pattern\n");

    if((hdr->extended_hdr.parsed_pkt.offset.payload_offset > 0)
       && (hdr->caplen > hdr->extended_hdr.parsed_pkt.offset.payload_offset)) {
      char *payload = (char *)&(skb->data[hdr->extended_hdr.parsed_pkt.offset.payload_offset /* -displ */ ]);
      int rc = 0, payload_len =
	hdr->caplen - hdr->extended_hdr.parsed_pkt.offset.payload_offset - displ;

      if(payload_len > 0) {
	int i;
	struct ts_state state;

	if(enable_debug) {
	  printk("[PF_RING] Trying to match pattern [caplen=%d][len=%d][displ=%d][payload_offset=%d][",
		 hdr->caplen, payload_len, displ,
		 hdr->extended_hdr.parsed_pkt.offset.payload_offset);

	  for(i = 0; i < payload_len; i++)
	    printk("[%d/%c]", i, payload[i] & 0xFF);
	  printk("]\n");
	}

	payload[payload_len] = '\0';

	if(enable_debug)
	  printk("[PF_RING] Attempt to match [%s]\n", payload);

	for(i = 0; (i < MAX_NUM_PATTERN) && (rule->pattern[i] != NULL); i++) {
	  if(enable_debug)
	    printk("[PF_RING] Attempt to match pattern %d\n", i);
	  rc = (textsearch_find_continuous
		(rule->pattern[i], &state,
		 payload, payload_len) != UINT_MAX) ? 1 : 0;
	  if(rc == 1)
	    break;
	}

	if(enable_debug)
	  printk("[PF_RING] Match returned: %d [payload_len=%d][%s]\n",
		 rc, payload_len, payload);

	if(rc == 0)
	  return(0);	/* No match */
      } else
	return(0);	/* No payload data */
    } else
      return(0);	/* No payload data */
  }
#endif

  /* Step 1 - Filter (optional) */
  if((rule->rule.extended_fields.filter_plugin_id > 0)
     && (rule->rule.extended_fields.filter_plugin_id < MAX_PLUGIN_ID)
     && (plugin_registration[rule->rule.extended_fields.filter_plugin_id] != NULL)
     && (plugin_registration[rule->rule.extended_fields.filter_plugin_id]->pfring_plugin_filter_skb != NULL)
     ) {
    int rc;

    if(enable_debug)
      printk("[PF_RING] rule->plugin_id [rule_id=%d]"
	     "[filter_plugin_id=%d][plugin_action=%d][ptr=%p]\n",
	     rule->rule.rule_id,
	     rule->rule.extended_fields.filter_plugin_id,
	     rule->rule.plugin_action.plugin_id,
	     plugin_registration[rule->rule.plugin_action.plugin_id]);

    rc = plugin_registration[rule->rule.extended_fields.filter_plugin_id]->pfring_plugin_filter_skb
      (pfr, rule, hdr, skb, displ, &parse_memory_buffer[rule->rule.extended_fields.filter_plugin_id]);

    if(parse_memory_buffer[rule->rule.extended_fields.filter_plugin_id])
      *free_parse_mem = 1;

    if(rc <= 0) {
      return(0); /* No match */
    } else {
      *last_matched_plugin = rule->rule.extended_fields.filter_plugin_id;
      hdr->extended_hdr.parsed_pkt.last_matched_plugin_id =
	rule->rule.extended_fields.filter_plugin_id;

      if(enable_debug)
	printk("[PF_RING] [last_matched_plugin = %d][buffer=%p][len=%d]\n",
	       *last_matched_plugin,
	       parse_memory_buffer[rule->rule.extended_fields.filter_plugin_id],
	       parse_memory_buffer[rule->rule.extended_fields.filter_plugin_id] ?
	       parse_memory_buffer[rule->rule.extended_fields.filter_plugin_id]->mem_len : 0);
    }
  }

  /* Step 2 - Handle skb */
  /* Action to be performed in case of match */
  if((rule->rule.plugin_action.plugin_id != NO_PLUGIN_ID)
     && (rule->rule.plugin_action.plugin_id < MAX_PLUGIN_ID)
     && (plugin_registration[rule->rule.plugin_action.plugin_id] != NULL)
     && (plugin_registration[rule->rule.plugin_action.plugin_id]->pfring_plugin_handle_skb != NULL)
     ) {
    int rc;

    if(enable_debug)
      printk("[PF_RING] Calling pfring_plugin_handle_skb(pluginId=%d)\n",
	     rule->rule.plugin_action.plugin_id);

    rc = plugin_registration[rule->rule.plugin_action.plugin_id]
      ->pfring_plugin_handle_skb(pfr, rule, NULL, hdr, skb, displ,
				 rule->rule.extended_fields.filter_plugin_id,
				 &parse_memory_buffer[rule->rule.extended_fields.filter_plugin_id],
				 behaviour);
    if(rc <= 0)
      return(0); /* No match */

    if(*last_matched_plugin == 0)
      *last_matched_plugin = rule->rule.plugin_action.plugin_id;

    if(parse_memory_buffer[rule->rule.plugin_action.plugin_id])
      *free_parse_mem = 1;
  } else {
    if(enable_debug)
      printk("[PF_RING] Skipping pfring_plugin_handle_skb(plugin_action=%d)\n",
	     rule->rule.plugin_action.plugin_id);
    *behaviour = rule->rule.rule_action;

    if(enable_debug)
      printk("[PF_RING] Rule %d behaviour: %d\n",
	     rule->rule.rule_id, rule->rule.rule_action);
  }

  if(enable_debug) {
    printk("[PF_RING] MATCH: match_filtering_rule(vlan=%u, proto=%u, sip=%u, sport=%u, dip=%u, dport=%u)\n",
	   hdr->extended_hdr.parsed_pkt.vlan_id, hdr->extended_hdr.parsed_pkt.l3_proto,
	   hdr->extended_hdr.parsed_pkt.ipv4_src, hdr->extended_hdr.parsed_pkt.l4_src_port,
	   hdr->extended_hdr.parsed_pkt.ipv4_dst, hdr->extended_hdr.parsed_pkt.l4_dst_port);
    printk("[PF_RING] [rule(vlan=%u, proto=%u, ip=%u-%u, port=%u-%u)(behaviour=%d)]\n",
	   rule->rule.core_fields.vlan_id,
	   rule->rule.core_fields.proto,
	   rule->rule.core_fields.host4_low,
	   rule->rule.core_fields.host4_high,
	   rule->rule.core_fields.port_low,
	   rule->rule.core_fields.port_high, *behaviour);
  }

  rule->rule.internals.jiffies_last_match = jiffies;

  return(1); /* match */
}

/* ********************************** */

/*
  Generic function for copying either a skb or a raw
  memory block to the ring buffer
  
  Return: 
  - 0 = packet was not copied (e.g. slot was full)
  - 1 = the packet was copied (i.e. there was room for it)
*/
inline int copy_data_to_ring(struct sk_buff *skb,
			     struct pf_ring_socket *pfr,
			     struct pfring_pkthdr *hdr,
			     int displ, int offset, void *plugin_mem,
			     void *raw_data, uint raw_data_len) {
  char *ring_bucket;
  u_int32_t off, taken;

  if(pfr->ring_slots == NULL) return(0);

  write_lock_bh(&pfr->ring_index_lock);
  // smp_rmb();

  off = pfr->slots_info->insert_off;
  pfr->slots_info->tot_pkts++;

  if(!check_and_init_free_slot(pfr, off)) /* Full */ {
    /* No room left */
    pfr->slots_info->tot_lost++;

    if(enable_debug)
      printk("[PF_RING] ==> slot(off=%d) is full [insert_off=%u][remove_off=%u][slot_len=%u][num_queued_pkts=%u]\n",
	     off, pfr->slots_info->insert_off, pfr->slots_info->remove_off, pfr->slots_info->slot_len, num_queued_pkts(pfr));

    write_unlock_bh(&pfr->ring_index_lock);
    return(0);
  }

  ring_bucket = get_slot(pfr, off);

  if(skb != NULL) {
    /* skb copy mode */

    if((plugin_mem != NULL) && (offset > 0)) {
      memcpy(&ring_bucket[pfr->slot_header_len], plugin_mem, offset);
    }

    if(hdr->caplen > 0) {
      if(enable_debug)
	printk("[PF_RING] --> [caplen=%d][len=%d][displ=%d][extended_hdr.parsed_header_len=%d][bucket_len=%d][sizeof=%d]\n",
	       hdr->caplen, hdr->len, displ, hdr->extended_hdr.parsed_header_len, pfr->bucket_len,
	       pfr->slot_header_len);

      skb_copy_bits(skb, -displ, &ring_bucket[pfr->slot_header_len + offset], hdr->caplen);
    } else {
      if(hdr->extended_hdr.parsed_header_len >= pfr->bucket_len) {
	static u_char print_once = 0;

	if(!print_once) {
	  printk("[PF_RING] WARNING: the bucket len is [%d] shorter than the plugin parsed header [%d]\n",
		 pfr->bucket_len, hdr->extended_hdr.parsed_header_len);
	  print_once = 1;
	}
      }
    }
  } else {
    /* Raw data copy mode */
    raw_data_len = min(raw_data_len, pfr->bucket_len); /* Avoid overruns */
    memcpy(&ring_bucket[pfr->slot_header_len], raw_data, raw_data_len); /* Copy raw data if present */
    hdr->len = hdr->caplen = raw_data_len, hdr->extended_hdr.if_index = FAKE_PACKET;
    /* printk("[PF_RING] Copied raw data at slot with offset %d [len=%d]\n", off, raw_data_len); */
  }

  memcpy(ring_bucket, hdr, pfr->slot_header_len); /* Copy extended packet header */

  pfr->slots_info->insert_off = get_next_slot_offset(pfr, off, &taken);

  if(enable_debug)
    printk("[PF_RING] ==> insert_off=%d\n", pfr->slots_info->insert_off);

  /*
    NOTE: smp_* barriers are _compiler_ barriers on UP, mandatory barriers on SMP
    a consumer _must_ see the new value of tot_insert only after the buffer update completes
  */
  smp_wmb();
  pfr->slots_info->tot_insert++;

  write_unlock_bh(&pfr->ring_index_lock);

  if(waitqueue_active(&pfr->ring_slots_waitqueue)
     && (num_queued_pkts(pfr) >= pfr->poll_num_pkts_watermark))
    wake_up_interruptible(&pfr->ring_slots_waitqueue);

#if(LINUX_VERSION_CODE > KERNEL_VERSION(2,6,32))
  /* Signaling on vPFRing's eventfd ctx when needed */
  if(pfr->vpfring_ctx && (!(pfr->slots_info->vpfring_guest_flags & VPFRING_GUEST_NO_INTERRUPT))) {
    eventfd_signal(pfr->vpfring_ctx, 1);
  }
#endif

  return(1);
}

/* ********************************** */

static int copy_raw_data_to_ring(struct pf_ring_socket *pfr,
				 struct pfring_pkthdr *dummy_hdr,
				 void *raw_data, uint raw_data_len) {
  return(copy_data_to_ring(NULL, pfr, dummy_hdr, 0, 0, NULL, raw_data, raw_data_len));
}

/* ********************************** */

static int add_pkt_to_ring(struct sk_buff *skb,
			    struct pf_ring_socket *_pfr,
			    struct pfring_pkthdr *hdr,
			    int displ, u_int8_t channel_id,
			    int offset, void *plugin_mem)
{
  struct pf_ring_socket *pfr = (_pfr->master_ring != NULL) ? _pfr->master_ring : _pfr;
  int32_t the_bit = 1 << channel_id;

  if(enable_debug)
    printk("[PF_RING] --> add_pkt_to_ring(len=%d) [pfr->channel_id=%d][channel_id=%d]\n",
	   hdr->len, pfr->channel_id, channel_id);

  if((!pfr->ring_active) || (!skb))
    return(0);

  if((pfr->channel_id != RING_ANY_CHANNEL)
     && (channel_id != RING_ANY_CHANNEL)
     && ((pfr->channel_id & the_bit) != the_bit))
    return(0); /* Wrong channel */

  hdr->caplen = min(pfr->bucket_len - offset, hdr->caplen);

  if(pfr->kernel_consumer_plugin_id
     && plugin_registration[pfr->kernel_consumer_plugin_id]->pfring_packet_reader) {
    write_lock_bh(&pfr->ring_index_lock); /* Serialize */
    plugin_registration[pfr->kernel_consumer_plugin_id]->pfring_packet_reader(pfr, skb, channel_id, hdr, displ);
    pfr->slots_info->tot_pkts++;
    write_unlock_bh(&pfr->ring_index_lock);
    return(0);
  }

  return(copy_data_to_ring(skb, pfr, hdr, displ, offset, plugin_mem, NULL, 0));
}

/* ********************************** */

static int add_packet_to_ring(struct pf_ring_socket *pfr, struct pfring_pkthdr *hdr,
			      struct sk_buff *skb,
			      int displ, u_int8_t parse_pkt_first)
{
  if(parse_pkt_first)
    parse_pkt(skb, displ, hdr, 0 /* Do not reset user-specified fields */);

  ring_read_lock();
  add_pkt_to_ring(skb, pfr, hdr, 0, RING_ANY_CHANNEL, displ, NULL);
  ring_read_unlock();
  return(0);
}

/* ********************************** */

static int add_hdr_to_ring(struct pf_ring_socket *pfr, struct pfring_pkthdr *hdr)
{
  return(add_packet_to_ring(pfr, hdr, NULL, 0, 0));
}

/* ********************************** */

/* Free filtering placeholders */
static void free_parse_memory(struct parse_buffer *parse_memory_buffer[])
{
  int i;

  for(i = 1; i <= max_registered_plugin_id; i++)
    if(parse_memory_buffer[i]) {
      if(parse_memory_buffer[i]->mem != NULL) {
	kfree(parse_memory_buffer[i]->mem);
      }

      kfree(parse_memory_buffer[i]);
    }
}

/* ********************************** */

static int reflect_packet(struct sk_buff *skb,
			  struct pf_ring_socket *pfr,
			  struct net_device *reflector_dev,
			  int displ,
			  rule_action_behaviour behaviour)
{
  if(enable_debug)
    printk("[PF_RING] reflect_packet called\n");

  if((reflector_dev != NULL)
     && (reflector_dev->flags & IFF_UP) /* Interface is up */ ) {
    int ret;

    skb->pkt_type = PACKET_OUTGOING, skb->dev = reflector_dev;
    /*
      Avoid others to free the skb and crash
      this because dev_queue_xmit (if successfull) is gonna
      call kfree_skb that will free the skb if users (see below)
      has not been incremented
    */
    atomic_inc(&skb->users);
    if(displ > 0) skb->data -= displ, skb->len += displ;

    if(behaviour == bounce_packet_and_stop_rule_evaluation) {
      char dst_mac[6];

      /* Swap mac addresses */
      memcpy(dst_mac, skb->data, 6);
      memcpy(skb->data, &skb->data[6], 6);
      memcpy(&skb->data[6], dst_mac, 6);
    }

    /*
      NOTE
      dev_queue_xmit() must be called with interrupts enabled
      which means it can't be called with spinlocks held.
    */
    ret = dev_queue_xmit(skb);
    if(displ > 0) skb->data += displ, skb->len -= displ;
    atomic_set(&pfr->num_ring_users, 0);	/* Done */
    /* printk("[PF_RING] --> ret=%d\n", ret); */

    if(ret == NETDEV_TX_OK)
      pfr->slots_info->tot_fwd_ok++;
    else {
      pfr->slots_info->tot_fwd_notok++;
      /*
	Do not put the statement below in case of success
	as dev_queue_xmit has already decremented users
      */
      atomic_dec(&skb->users);
    }

    /* yield(); */
    return(ret == NETDEV_TX_OK ? 0 : -ENETDOWN);
  } else
    pfr->slots_info->tot_fwd_notok++;

  return(-ENETDOWN);
}

/* ********************************** */

int check_perfect_rules(struct sk_buff *skb,
			struct pf_ring_socket *pfr,
			struct pfring_pkthdr *hdr,
			int *fwd_pkt,
			u_int8_t *free_parse_mem,
			struct parse_buffer *parse_memory_buffer[MAX_PLUGIN_ID],
			int displ, u_int *last_matched_plugin)
{
  u_int hash_idx;
  sw_filtering_hash_bucket *hash_bucket;
  u_int8_t hash_found = 0;

  hash_idx = hash_pkt_header(hdr, 0, 0) % DEFAULT_RING_HASH_SIZE;
  hash_bucket = pfr->sw_filtering_hash[hash_idx];

  while(hash_bucket != NULL) {
    if(hash_bucket_match(hash_bucket, hdr, 0, 0)) {
      hash_found = 1;
      break;
    } else
      hash_bucket = hash_bucket->next;
  } /* while */

  if(hash_found) {
    rule_action_behaviour behaviour = forward_packet_and_stop_rule_evaluation;

    if((hash_bucket->rule.plugin_action.plugin_id != NO_PLUGIN_ID)
       && (hash_bucket->rule.plugin_action.plugin_id < MAX_PLUGIN_ID)
       && (plugin_registration[hash_bucket->rule.plugin_action.plugin_id] != NULL)
       && (plugin_registration[hash_bucket->rule.plugin_action.plugin_id]->
	   pfring_plugin_handle_skb != NULL)
       ) {
      plugin_registration[hash_bucket->rule.plugin_action.plugin_id]
	->pfring_plugin_handle_skb(pfr, NULL, hash_bucket, hdr, skb, displ, 0, /* no plugin */
				   &parse_memory_buffer[hash_bucket->rule.plugin_action.plugin_id],
				   &behaviour);

      if(parse_memory_buffer[hash_bucket->rule.plugin_action.plugin_id])
	*free_parse_mem = 1;
      *last_matched_plugin = hash_bucket->rule.plugin_action.plugin_id;
      hdr->extended_hdr.parsed_pkt.last_matched_plugin_id = hash_bucket->rule.plugin_action.plugin_id;
    } else
      behaviour = hash_bucket->rule.rule_action;

    switch(behaviour) {
    case forward_packet_and_stop_rule_evaluation:
      *fwd_pkt = 1;
      break;
    case dont_forward_packet_and_stop_rule_evaluation:
      *fwd_pkt = 0;
      break;
    case execute_action_and_stop_rule_evaluation:
      *fwd_pkt = 0;
      break;
    case execute_action_and_continue_rule_evaluation:
      *fwd_pkt = 0;
      hash_found = 0;	/* This way we also evaluate the list of rules */
      break;
    case forward_packet_add_rule_and_stop_rule_evaluation:
      *fwd_pkt = 1;
      break;
    case reflect_packet_and_stop_rule_evaluation:
    case bounce_packet_and_stop_rule_evaluation:
      *fwd_pkt = 0;
      reflect_packet(skb, pfr, hash_bucket->rule.internals.reflector_dev, displ, behaviour);
      break;
    case reflect_packet_and_continue_rule_evaluation:
    case bounce_packet_and_continue_rule_evaluation:
      *fwd_pkt = 0;
      reflect_packet(skb, pfr, hash_bucket->rule.internals.reflector_dev, displ, behaviour);
      hash_found = 0;	/* This way we also evaluate the list of rules */
      break;
    }
  } else {
    /* printk("[PF_RING] Packet not found\n"); */
  }

  return(hash_found);
}

/* ********************************** */

int check_wildcard_rules(struct sk_buff *skb,
			 struct pf_ring_socket *pfr,
			 struct pfring_pkthdr *hdr,
			 int *fwd_pkt,
			 u_int8_t *free_parse_mem,
			 struct parse_buffer *parse_memory_buffer[MAX_PLUGIN_ID],
			 int displ, u_int *last_matched_plugin)
{
  struct list_head *ptr, *tmp_ptr;

  list_for_each_safe(ptr, tmp_ptr, &pfr->sw_filtering_rules) {
    sw_filtering_rule_element *entry;
    rule_action_behaviour behaviour = forward_packet_and_stop_rule_evaluation;

    entry = list_entry(ptr, sw_filtering_rule_element, list);

    if(match_filtering_rule(pfr, entry, hdr, skb, displ,
			    parse_memory_buffer, free_parse_mem,
			    last_matched_plugin, &behaviour)) {
      if(enable_debug)
	printk("[PF_RING] behaviour=%d\n", behaviour);

      hdr->extended_hdr.parsed_pkt.last_matched_rule_id = entry->rule.rule_id;

      if(behaviour == forward_packet_and_stop_rule_evaluation) {
	*fwd_pkt = 1;
	break;
      } else if(behaviour == forward_packet_add_rule_and_stop_rule_evaluation) {
	sw_filtering_hash_bucket *hash_bucket;

	*fwd_pkt = 1;
	hash_bucket = (sw_filtering_hash_bucket *)kcalloc(1, sizeof(sw_filtering_hash_bucket),
							  GFP_ATOMIC);

	if(hash_bucket) {
	  int rc = 0;

	  if(*last_matched_plugin
	     && plugin_registration[*last_matched_plugin] != NULL
	     && plugin_registration[*last_matched_plugin]->pfring_plugin_add_rule != NULL
	     && (plugin_registration[*last_matched_plugin]->pfring_plugin_add_rule(entry, hdr, hash_bucket) == 0) ) {
	    if(enable_debug) {
	      printk("pfring_plugin_add_rule(entry, hdr, hash_bucket) done!\n");
	    }
	  } else {
	    hash_bucket->rule.vlan_id = hdr->extended_hdr.parsed_pkt.vlan_id;
	    hash_bucket->rule.proto = hdr->extended_hdr.parsed_pkt.l3_proto;
	    hash_bucket->rule.host4_peer_a = hdr->extended_hdr.parsed_pkt.ipv4_src;
	    hash_bucket->rule.host4_peer_b = hdr->extended_hdr.parsed_pkt.ipv4_dst;
	    hash_bucket->rule.port_peer_a = hdr->extended_hdr.parsed_pkt.l4_src_port;
	    hash_bucket->rule.port_peer_b = hdr->extended_hdr.parsed_pkt.l4_dst_port;
	    hash_bucket->rule.rule_action = forward_packet_and_stop_rule_evaluation;
	    hash_bucket->rule.reflector_device_name[0] = '\0';
	    hash_bucket->rule.internals.jiffies_last_match = jiffies; /* Avoid immediate rule purging */
	    hash_bucket->rule.internals.reflector_dev = NULL;
	    hash_bucket->rule.plugin_action.plugin_id = NO_PLUGIN_ID;
	  }

	  write_lock(&pfr->ring_rules_lock);
	  rc = pfr->handle_hash_rule(pfr, hash_bucket, 1 /* add_rule_from_plugin */);

	  if((rc != 0) && (rc != -EEXIST)) {
	    write_unlock(&pfr->ring_rules_lock);
	    kfree(hash_bucket);
	    return(-1);
	  } else {
	    if(rc != -EEXIST) /* Rule already existing */
	      pfr->num_sw_filtering_rules++;

	    write_unlock(&pfr->ring_rules_lock);

	    if(enable_debug)
	      printk("[PF_RING] Added rule: [%d.%d.%d.%d:%d <-> %d.%d.%d.%d:%d][tot_rules=%d]\n",
		     ((hash_bucket->rule.host4_peer_a >> 24) & 0xff), ((hash_bucket->rule.host4_peer_a >> 16) & 0xff),
		     ((hash_bucket->rule.host4_peer_a >> 8) & 0xff), ((hash_bucket->rule.host4_peer_a >> 0) & 0xff),
		     hash_bucket->rule.port_peer_a, ((hash_bucket->rule.host4_peer_b >> 24) & 0xff),
		     ((hash_bucket->rule.host4_peer_b >> 16) & 0xff), ((hash_bucket->rule.host4_peer_b >> 8) & 0xff),
		     ((hash_bucket->rule.host4_peer_b >> 0) & 0xff), hash_bucket->rule.port_peer_b, pfr->num_sw_filtering_rules);
	  }
	}
	break;
      } else if(behaviour == dont_forward_packet_and_stop_rule_evaluation) {
	*fwd_pkt = 0;
	break;
      }

      if(entry->rule.rule_action == forward_packet_and_stop_rule_evaluation) {
	*fwd_pkt = 1;
	break;
      } else if(entry->rule.rule_action == dont_forward_packet_and_stop_rule_evaluation) {
	*fwd_pkt = 0;
	break;
      } else if(entry->rule.rule_action == execute_action_and_stop_rule_evaluation) {
	printk("[PF_RING] *** execute_action_and_stop_rule_evaluation\n");
	break;
      } else if(entry->rule.rule_action == execute_action_and_continue_rule_evaluation) {
	/* The action has already been performed inside match_filtering_rule()
	   hence instead of stopping rule evaluation, the next rule
	   will be evaluated */
      } else if((entry->rule.rule_action == reflect_packet_and_stop_rule_evaluation)
		|| (entry->rule.rule_action == bounce_packet_and_stop_rule_evaluation)) {
	*fwd_pkt = 0;
	reflect_packet(skb, pfr, entry->rule.internals.reflector_dev, displ, entry->rule.rule_action);
	break;
      } else if((entry->rule.rule_action == reflect_packet_and_continue_rule_evaluation)
		|| (entry->rule.rule_action == bounce_packet_and_continue_rule_evaluation)) {
	*fwd_pkt = 1;
	reflect_packet(skb, pfr, entry->rule.internals.reflector_dev, displ, entry->rule.rule_action);
      }
    }
  }  /* for */

  return(0);
}

/* ********************************** */

/*
 * add_skb_to_ring()
 *
 * Add the specified skb to the ring so that userland apps/plugins
 * can use the packet.
 *
 * Return code:
 *  0 packet successully processed but no room in the ring
 *  1 packet successully processed and available room in the ring
 * -1  processing error (e.g. the packet has been discarded by
 *                       filter, ring not active...)
 *
 */
static int add_skb_to_ring(struct sk_buff *skb,
			   struct pf_ring_socket *pfr,
			   struct pfring_pkthdr *hdr,
			   int is_ip_pkt, int displ,
			   u_int8_t channel_id,
			   u_int8_t num_rx_channels)
{
  int fwd_pkt = 0, rc = 0;
  struct parse_buffer *parse_memory_buffer[MAX_PLUGIN_ID] = { NULL };
  u_int8_t free_parse_mem = 0;
  u_int last_matched_plugin = 0;
  u_int8_t hash_found = 0;

  /* This is a memory holder for storing parsed packet information
     that will then be freed when the packet has been handled
  */

  if(enable_debug)
    printk("[PF_RING] --> add_skb_to_ring(len=%d) [channel_id=%d/%d][active=%d][%s]\n",
	   hdr->len, channel_id, num_rx_channels,
	   pfr->ring_active, pfr->ring_netdev->dev->name);

  if((!pfring_enabled) || ((!pfr->ring_active) && (pfr->master_ring == NULL)))
    return(-1);

  pfr->num_rx_channels = num_rx_channels; /* Constantly updated */
  hdr->extended_hdr.parsed_pkt.last_matched_rule_id = (u_int16_t)-1;

  atomic_set(&pfr->num_ring_users, 1);

  /* [1] BPF Filtering (from af_packet.c) */
  if(pfr->bpfFilter != NULL) {
    unsigned res = 1, len;
    u8 *skb_head = skb->data;
    int skb_len = skb->len;

    len = skb->len - skb->data_len;

    if(displ > 0) {
      /*
	Move off the offset (we modify the packet for the sake of filtering)
	thus we need to restore it later on

	NOTE: displ = 0 | skb_network_offset(skb)
      */
      skb_push(skb, displ);
    }

    rcu_read_lock_bh();
    res = sk_run_filter(skb, pfr->bpfFilter->insns, skb->len);
    rcu_read_unlock_bh();

    /* Restore */
    if(displ > 0)
      skb->data = skb_head, skb->len = skb_len;

    if(res == 0) {
      /* Filter failed */
      if(enable_debug)
	printk("[PF_RING] add_skb_to_ring(skb): Filter failed [len=%d][tot=%llu]"
	       "[insert_off=%d][pkt_type=%d][cloned=%d]\n",
	       (int)skb->len, pfr->slots_info->tot_pkts,
	       pfr->slots_info->insert_off, skb->pkt_type,
	       skb->cloned);

      atomic_set(&pfr->num_ring_users, 0);
      return(-1);
    }
  }

  if(enable_debug) {
    printk("[PF_RING] add_skb_to_ring: [%s][displ=%d][len=%d][caplen=%d]"
	   "[is_ip_pkt=%d][%d -> %d][%p/%p]\n",
	   (skb->dev->name != NULL) ? skb->dev->name : "<NULL>",
	   displ, hdr->len, hdr->caplen,
	   is_ip_pkt, hdr->extended_hdr.parsed_pkt.l4_src_port,
	   hdr->extended_hdr.parsed_pkt.l4_dst_port, skb->dev,
	   pfr->ring_netdev);

    /* ************************************* */

    printk("[PF_RING] add_skb_to_ring(skb) [len=%d][tot=%llu][insert_off=%d]"
	   "[pkt_type=%d][cloned=%d]\n",
	   (int)skb->len, pfr->slots_info->tot_pkts,
	   pfr->slots_info->insert_off, skb->pkt_type, skb->cloned);
  }

  /* Extensions */
  fwd_pkt = pfr->sw_filtering_rules_default_accept_policy;
  /* printk("[PF_RING] rules_default_accept_policy: [fwd_pkt=%d]\n", fwd_pkt); */

  /* ************************** */

  /* [2] Filter packet according to rules */
  if(enable_debug)
    printk("[PF_RING] About to evaluate packet [len=%d][tot=%llu][insert_off=%d]"
	   "[pkt_type=%d][cloned=%d]\n", (int)skb->len,
	   pfr->slots_info->tot_pkts, pfr->slots_info->insert_off,
	   skb->pkt_type, skb->cloned);

  /* [2.1] Search the hash */
  if(pfr->sw_filtering_hash != NULL)
    hash_found = check_perfect_rules(skb, pfr, hdr, &fwd_pkt, &free_parse_mem,
				     parse_memory_buffer, displ, &last_matched_plugin);

  /* [2.2] Search rules list */
  if((!hash_found) && (pfr->num_sw_filtering_rules > 0)) {
    int rc = check_wildcard_rules(skb, pfr, hdr, &fwd_pkt, &free_parse_mem,
				  parse_memory_buffer, displ, &last_matched_plugin);

    if(rc != 0)
      fwd_pkt = 0;
  }

  if(fwd_pkt) {
    /* We accept the packet: it needs to be queued */
    if(enable_debug)
      printk("[PF_RING] Forwarding packet to userland\n");

    /* [3] Packet sampling */
    if(pfr->sample_rate > 1) {
      write_lock_bh(&pfr->ring_index_lock);
      pfr->slots_info->tot_pkts++;

      if(pfr->pktToSample <= 1) {
	pfr->pktToSample = pfr->sample_rate;
      } else {
	pfr->pktToSample--;

	if(enable_debug)
	  printk("[PF_RING] add_skb_to_ring(skb): sampled packet [len=%d]"
		 "[tot=%llu][insert_off=%d][pkt_type=%d][cloned=%d]\n",
		 (int)skb->len, pfr->slots_info->tot_pkts,
		 pfr->slots_info->insert_off, skb->pkt_type,
		 skb->cloned);

	write_unlock_bh(&pfr->ring_index_lock);

	if(free_parse_mem)
	  free_parse_memory(parse_memory_buffer);

	atomic_set(&pfr->num_ring_users, 0);
	return(-1);
      }

      write_unlock_bh(&pfr->ring_index_lock);
    }

    if(hdr->caplen > 0) {
      /* Copy the packet into the bucket */
      int offset;
      void *mem;

      if((last_matched_plugin > 0)
	 && (parse_memory_buffer[last_matched_plugin] != NULL)) {
	offset = hdr->extended_hdr.parsed_header_len = parse_memory_buffer[last_matched_plugin]->mem_len;

	hdr->extended_hdr.parsed_pkt.last_matched_plugin_id = last_matched_plugin;

	if(enable_debug)
	  printk("[PF_RING] --> [last_matched_plugin = %d][extended_hdr.parsed_header_len=%d]\n",
		 last_matched_plugin, hdr->extended_hdr.parsed_header_len);

	if(offset > pfr->bucket_len)
	  offset = hdr->extended_hdr.parsed_header_len = pfr->bucket_len;

	mem = parse_memory_buffer[last_matched_plugin]->mem;
      } else
	offset = 0, hdr->extended_hdr.parsed_header_len = 0, mem = NULL;

      rc = add_pkt_to_ring(skb, pfr, hdr, displ, channel_id, offset, mem);
    }
  }

  if(enable_debug)
    printk("[PF_RING] [pfr->slots_info->insert_off=%d]\n",
	   pfr->slots_info->insert_off);

  if(free_parse_mem)
    free_parse_memory(parse_memory_buffer);

  atomic_set(&pfr->num_ring_users, 0);

  return(rc);
}

/* ********************************** */

static u_int hash_pkt_cluster(ring_cluster_element * cluster_ptr,
			      struct pfring_pkthdr *hdr)
{
  u_int idx;

  if(cluster_ptr->cluster.hashing_mode == cluster_round_robin) {
    idx = cluster_ptr->cluster.hashing_id++;
  } else {
    /* Per-flow clustering */
    idx = hash_pkt_header(hdr, 0, 0);
  }

  return(idx % cluster_ptr->cluster.num_cluster_elements);
}

/* ********************************** */

static int register_plugin(struct pfring_plugin_registration *reg)
{
  if(reg == NULL)
    return(-1);

  if(enable_debug)
    printk("[PF_RING] --> register_plugin(%d)\n", reg->plugin_id);

  if((reg->plugin_id >= MAX_PLUGIN_ID) || (reg->plugin_id == 0))
    return(-EINVAL);

  if(plugin_registration[reg->plugin_id] != NULL)
    return(-EINVAL);	/* plugin already registered */

  if(reg->pfring_plugin_register == NULL)
    printk("[PF_RING] WARNING: plugin %d does not implement handle pfring_plugin_register: please fix it\n",
	   reg->plugin_id);

  plugin_registration[reg->plugin_id] = reg;
  plugin_registration_size++;

  max_registered_plugin_id =
    max(max_registered_plugin_id, reg->plugin_id);

  printk("[PF_RING] registered plugin [id=%d][max=%d][%p]\n",
	 reg->plugin_id, max_registered_plugin_id,
	 plugin_registration[reg->plugin_id]);
  try_module_get(THIS_MODULE);	/* Increment usage count */
  return(0);
}

/* ********************************** */

int unregister_plugin(u_int16_t pfring_plugin_id)
{
  int i;

  if(pfring_plugin_id >= MAX_PLUGIN_ID)
    return(-EINVAL);

  if(plugin_registration[pfring_plugin_id] == NULL)
    return(-EINVAL);	/* plugin not registered */
  else {
    struct list_head *ptr, *tmp_ptr, *ring_ptr, *ring_tmp_ptr;

    plugin_registration[pfring_plugin_id] = NULL;
    plugin_registration_size--;

    ring_read_lock();
    list_for_each_safe(ring_ptr, ring_tmp_ptr, &ring_table) {
      struct ring_element *entry =
	list_entry(ring_ptr, struct ring_element, list);
      struct pf_ring_socket *pfr = ring_sk(entry->sk);

      list_for_each_safe(ptr, tmp_ptr, &pfr->sw_filtering_rules) {
	sw_filtering_rule_element *rule;

	rule = list_entry(ptr, sw_filtering_rule_element, list);

	if(rule->rule.plugin_action.plugin_id == pfring_plugin_id) {
	  if(plugin_registration[pfring_plugin_id]
	     && plugin_registration[pfring_plugin_id]->pfring_plugin_free_ring_mem) {
	    /* Custom free function */
	    plugin_registration[pfring_plugin_id]->pfring_plugin_free_ring_mem(rule);
	  } else {
	    if(rule->plugin_data_ptr !=
	       NULL) {
	      kfree(rule->plugin_data_ptr);
	      rule->plugin_data_ptr = NULL;
	    }
	  }

	  rule->rule.plugin_action.plugin_id = NO_PLUGIN_ID;
	}
      }
    }
    ring_read_unlock();

    for(i = MAX_PLUGIN_ID - 1; i > 0; i--) {
      if(plugin_registration[i] != NULL) {
	max_registered_plugin_id = i;
	break;
      }
    }

    printk("[PF_RING] unregistered plugin [id=%d][max=%d]\n",
	   pfring_plugin_id, max_registered_plugin_id);
    module_put(THIS_MODULE);	/* Decrement usage count */
    return(0);
  }
}

/* ********************************** */

inline int is_valid_skb_direction(packet_direction direction, u_char recv_packet) {
  switch(direction) {
  case rx_and_tx_direction:
    return(1);
  case rx_only_direction:
    if(recv_packet) return(1);
    break;
  case tx_only_direction:
    if(!recv_packet) return(1);
    break;
  }

  return(0);
}

/* ********************************** */

static struct sk_buff* defrag_skb(struct sk_buff *skb,
				  u_int16_t displ,
				  struct pfring_pkthdr *hdr) {
  struct sk_buff *cloned = NULL;
  struct iphdr *iphdr = NULL;
  struct sk_buff *skk = NULL;

  skb_reset_network_header(skb);
  skb_reset_transport_header(skb);
  skb_set_network_header(skb, ETH_HLEN - displ);

  iphdr = ip_hdr(skb);

  if(iphdr && (iphdr->version == 4)) {
    if(enable_debug)
      printk("[PF_RING] [version=%d] %X -> %X\n",
	     iphdr->version, iphdr->saddr, iphdr->daddr);

    if(iphdr->frag_off & htons(IP_MF | IP_OFFSET)) {
      if((cloned = skb_clone(skb, GFP_ATOMIC)) != NULL) {
	if(enable_debug) {
	  int offset = ntohs(iphdr->frag_off);
	  offset &= IP_OFFSET;
	  offset <<= 3;

	  printk("[PF_RING] There is a fragment to handle [proto=%d][frag_off=%u]"
		 "[ip_id=%u][network_header=%d][displ=%d]\n",
		 iphdr->protocol, offset,
		 ntohs(iphdr->id),
		 hdr->extended_hdr.parsed_pkt.offset.l3_offset - displ, displ);
	}
	skk = ring_gather_frags(cloned);

	if(skk != NULL) {
	  if(enable_debug)
	    printk("[PF_RING] IP reasm on new skb [skb_len=%d]"
		   "[head_len=%d][nr_frags=%d][frag_list=%p]\n",
		   (int)skk->len,
		   skb_headlen(skk),
		   skb_shinfo(skk)->nr_frags,
		   skb_shinfo(skk)->frag_list);

	  skb = skk;
	  parse_pkt(skb, displ, hdr, 1);
	  hdr->len = hdr->caplen = skb->len + displ;
	  return(skb);
	} else {
	  //printk("[PF_RING] Fragment queued \n");
	  return(NULL);	/* mask rcvd fragments */
	}
      }
    } else {
      if(enable_debug)
	printk("[PF_RING] Do not seems to be a fragmented ip_pkt[iphdr=%p]\n",
	       iphdr);
    }
  } else if(iphdr && iphdr->version == 6) {
    /* Re-assembling fragmented IPv6 packets has not been
       implemented. Probability of observing fragmented IPv6
       packets is extremely low. */
    if(enable_debug)
      printk("[PF_RING] Re-assembling fragmented IPv6 packet hs not been implemented\n");
  }

  return(NULL);
}

/* ********************************** */

/*
  PF_RING main entry point 

  Return code
  0 - Packet not handled
  1 - Packet handled successfully
  2 - Packet handled successfully but unable to copy it into
      the ring due to lack of available space
*/

static int skb_ring_handler(struct sk_buff *skb,
			    u_char recv_packet,
			    u_char real_skb /* 1=real skb, 0=faked skb */ ,
			    u_int8_t channel_id,
			    u_int8_t num_rx_channels)
{
  struct sock *skElement;
  int rc = 0, is_ip_pkt, room_available = 0;
  struct list_head *ptr;
  struct pfring_pkthdr hdr;
  int displ;
  struct sk_buff *skk = NULL;
  struct sk_buff *orig_skb = skb;

  /* Check if there's at least one PF_RING ring defined that
     could receive the packet: if none just stop here */

  if(ring_table_size == 0) 
    return(rc);

  if(enable_debug) {
    if(skb->dev && (skb->dev->ifindex < MAX_NUM_IFIDX))
      printk("[PF_RING] --> skb_ring_handler(%s): %d rings [num_any_rings=%d]\n",
	     skb->dev->name, num_rings_per_device[skb->dev->ifindex], num_any_rings);
  }

  if((num_any_rings == 0)
     && (skb->dev
	 && (skb->dev->ifindex < MAX_NUM_IFIDX)
	 && (num_rings_per_device[skb->dev->ifindex] == 0)))
    return(rc);

#ifdef PROFILING
  uint64_t rdt = _rdtsc(), rdt1, rdt2;
#endif

#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30))
  channel_id = skb_get_rx_queue(skb);
#endif

  if(enable_debug)

    if((!skb) /* Invalid skb */ ||((!enable_tx_capture) && (!recv_packet))) {
      /*
	An outgoing packet is about to be sent out
	but we decided not to handle transmitted
	packets.
      */
      return(0);
    }

  if(enable_debug) {
    struct timeval tv;

    skb_get_timestamp(skb, &tv);
    printk("[PF_RING] skb_ring_handler() [skb=%p][%u.%u][len=%d][dev=%s][csum=%u]\n",
	   skb, (unsigned int)tv.tv_sec, (unsigned int)tv.tv_usec,
	   skb->len, skb->dev == NULL ? "<NULL>" : skb->dev->name,
	   skb->csum);
  }

#ifdef PROFILING
  rdt1 = _rdtsc();
#endif

  if(recv_packet) {
    /* Hack for identifying a packet received by the e1000 */
    if(real_skb)
      displ = SKB_DISPLACEMENT;
    else
      displ = 0;	/* Received by the e1000 wrapper */
  } else
    displ = 0;

  is_ip_pkt = parse_pkt(skb, displ, &hdr, 1);

  if(enable_ip_defrag) {
    if(real_skb
       && is_ip_pkt
       && recv_packet
       && (ring_table_size > 0)) {
      skb = defrag_skb(skb, displ, &hdr);

      if(skb == NULL)
	return(0);
    }
  }

  /* BD - API changed for time keeping */
#if(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,14))
  if(skb->stamp.tv_sec == 0)
    do_gettimeofday(&skb->stamp);  /* If timestamp is missing add it */
  hdr.ts.tv_sec = skb->stamp.tv_sec, hdr.ts.tv_usec = skb->stamp.tv_usec;
  hdr.extended_hdr.timestamp_ns = 0; /* No nsec for old kernels */
#elif(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22))
  if(skb->tstamp.off_sec == 0)
    __net_timestamp(skb); /* If timestamp is missing add it */
  hdr.ts.tv_sec = skb->tstamp.off_sec, hdr.ts.tv_usec = skb->tstamp.off_usec;
  hdr.extended_hdr.timestamp_ns = 0; /* No nsec for old kernels */
#else /* 2.6.22 and above */
  if(skb->tstamp.tv64 == 0)
    __net_timestamp(skb); /* If timestamp is missing add it */
  hdr.ts = ktime_to_timeval(skb->tstamp);

#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30))
  {
    /* Use hardware timestamps when present. If not, just use software timestamps */
    hdr.extended_hdr.timestamp_ns = ktime_to_ns(skb_hwtstamps(skb)->hwtstamp);

    if(enable_debug)
      printk("[PF_RING] hwts=%llu/dev=%s\n",
	     hdr.extended_hdr.timestamp_ns,
	     skb->dev ? skb->dev->name : "???");
  }
#endif
  if(hdr.extended_hdr.timestamp_ns == 0)
    hdr.extended_hdr.timestamp_ns = ktime_to_ns(skb->tstamp);
#endif

  hdr.len = hdr.caplen = skb->len + displ;

  if(skb->dev)
    hdr.extended_hdr.if_index = skb->dev->ifindex;
  else
    hdr.extended_hdr.if_index = -1;

  /* Avoid the ring to be manipulated while playing with it */
  ring_read_lock();

  /* [1] Check unclustered sockets */
  list_for_each(ptr, &ring_table) {
    struct pf_ring_socket *pfr;
    struct ring_element *entry;

    entry = list_entry(ptr, struct ring_element, list);

    skElement = entry->sk;
    pfr = ring_sk(skElement);

    if((pfr != NULL)
       && ((pfr->ring_netdev->dev == skb->dev)
	   || (pfr->ring_netdev == &any_device_element) /* Socket bound to 'any' */
	   || ((skb->dev->flags & IFF_SLAVE) && (pfr->ring_netdev->dev == skb->dev->master)))
       && (pfr->ring_netdev != &none_device_element) /* Not a dummy socket bound to "none" */
       && (pfr->cluster_id == 0 /* No cluster */ )
       && (pfr->ring_slots != NULL)
       && is_valid_skb_direction(pfr->direction, recv_packet)
       ) {
      /* We've found the ring where the packet can be stored */
      int old_caplen = hdr.caplen;  /* Keep old lenght */
      hdr.caplen = min(hdr.caplen, pfr->bucket_len);
      room_available |= add_skb_to_ring(skb, pfr, &hdr, is_ip_pkt, 
					displ, channel_id, num_rx_channels);
      hdr.caplen = old_caplen;
      rc = 1;	/* Ring found: we've done our job */
    }
  }

  /* [2] Check socket clusters */
  list_for_each(ptr, &ring_cluster_list) {
    ring_cluster_element *cluster_ptr;
    struct pf_ring_socket *pfr;

    cluster_ptr = list_entry(ptr, ring_cluster_element, list);

    if(cluster_ptr->cluster.num_cluster_elements > 0) {
      u_int skb_hash = hash_pkt_cluster(cluster_ptr, &hdr);
      u_short num_iterations;

      /*
	We try to add the packet to the right cluster
	element, but if we're working in round-robin and this
	element is full, we try to add this to the next available
	element. If none with at least a free slot can be found
	then we give up :-(
      */

      for(num_iterations = 0;
	  num_iterations < cluster_ptr->cluster.num_cluster_elements;
	  num_iterations++) {

	skElement = cluster_ptr->cluster.sk[skb_hash];

	if(skElement != NULL) {
	  pfr = ring_sk(skElement);

	  if((pfr != NULL)
	     && (pfr->ring_slots != NULL)
	     && ((pfr->ring_netdev->dev == skb->dev)
		 || ((skb->dev->flags & IFF_SLAVE)
		     && (pfr->ring_netdev->dev == skb->dev->master)))
	     && is_valid_skb_direction(pfr->direction, recv_packet)
	     ) {
	    if(check_and_init_free_slot(pfr, pfr->slots_info->insert_off) /* Not full */) {
	      /* We've found the ring where the packet can be stored */
	      room_available |= add_skb_to_ring(skb, pfr, &hdr, is_ip_pkt, 
						displ, channel_id, num_rx_channels);
	      rc = 1; /* Ring found: we've done our job */
	      break;
	    }
	  }
	}

	if(cluster_ptr->cluster.hashing_mode != cluster_round_robin)
	  break;
	else
	  skb_hash = (skb_hash + 1) % cluster_ptr->cluster.num_cluster_elements;
      }
    }
  } /* Clustering */

  ring_read_unlock();

#ifdef PROFILING
  rdt1 = _rdtsc() - rdt1;
  rdt2 = _rdtsc();
#endif

  /* Fragment handling */
  if(skk != NULL)
    kfree_skb(skk);

  if(rc == 1) {
    if(transparent_mode != driver2pf_ring_non_transparent) {
      rc = 0;
    } else {
      if(recv_packet && real_skb) {
	if(enable_debug)
	  printk("[PF_RING] kfree_skb()\n");

	kfree_skb(orig_skb);
      }
    }
  }

#ifdef PROFILING
  rdt2 = _rdtsc() - rdt2;
  rdt = _rdtsc() - rdt;

  if(enable_debug)
    printk("[PF_RING] # cycles: %d [lock costed %d %d%%][free costed %d %d%%]\n",
	   (int)rdt, rdt - rdt1,
	   (int)((float)((rdt - rdt1) * 100) / (float)rdt), rdt2,
	   (int)((float)(rdt2 * 100) / (float)rdt));
#endif

  //printk("[PF_RING] Returned %d\n", rc);
  
  if((rc == 1) && (room_available == 0))
    rc = 2;

  return(rc);		/*  0 = packet not handled */
}

/* ********************************** */

struct sk_buff skb;

static int buffer_ring_handler(struct net_device *dev, char *data, int len)
{
  if(enable_debug)
    printk("[PF_RING] buffer_ring_handler: [dev=%s][len=%d]\n",
	   dev->name == NULL ? "<NULL>" : dev->name, len);

  skb.dev = dev, skb.len = len, skb.data = data, skb.data_len = len;

  /* BD - API changed for time keeping */
#if(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,14))
  skb.stamp.tv_sec = 0;
#elif(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22))
  skb.tstamp.off_sec = 0;
#else
  skb.tstamp.tv64 = 0;
#endif

  return(skb_ring_handler(&skb, 1, 0 /* fake skb */ ,
			  UNKNOWN_RX_CHANNEL,
			  UNKNOWN_NUM_RX_CHANNELS));
}

/* ************************************* */

static void free_filtering_rule(filtering_rule * rule)
{
  if(rule->internals.reflector_dev != NULL)
    dev_put(rule->internals.reflector_dev);	/* Release device */

  if(rule->extended_fields.filter_plugin_id > 0) {
    if(plugin_registration[rule->extended_fields.filter_plugin_id]->pfring_plugin_register)
      plugin_registration[rule->extended_fields.filter_plugin_id]->pfring_plugin_register(0);
  }

  if(rule->plugin_action.plugin_id > 0) {
    if(plugin_registration[rule->plugin_action.plugin_id]->pfring_plugin_register)
      plugin_registration[rule->plugin_action.plugin_id]->pfring_plugin_register(0);
  }
}

/* ************************************* */

static void free_sw_filtering_hash_bucket(sw_filtering_hash_bucket * bucket)
{
  if(bucket->plugin_data_ptr)
    kfree(bucket->plugin_data_ptr);

  if(bucket->rule.internals.reflector_dev != NULL)
    dev_put(bucket->rule.internals.reflector_dev);	/* Release device */

  if(bucket->rule.plugin_action.plugin_id > 0) {
    if(plugin_registration[bucket->rule.plugin_action.plugin_id]->pfring_plugin_register)
      plugin_registration[bucket->rule.plugin_action.plugin_id]->pfring_plugin_register(0);
  }
}

/*
  NOTE

  I jeopardize the get_coalesce/set_eeprom fields for my purpose
  until hw filtering support is part of the kernel

*/

/* ************************************* */

static int handle_sw_filtering_hash_bucket(struct pf_ring_socket *pfr,
					   sw_filtering_hash_bucket * rule,
					   u_char add_rule)
{
  u_int32_t hash_value = hash_pkt(rule->rule.vlan_id, rule->rule.proto,
				  rule->rule.host_peer_a, rule->rule.host_peer_b,
				  rule->rule.port_peer_a, rule->rule.port_peer_b) 
    % DEFAULT_RING_HASH_SIZE;
  int rc = -1;

  if(enable_debug)
    printk("[PF_RING] handle_sw_filtering_hash_bucket(vlan=%u, proto=%u, "
	   "sip=%d.%d.%d.%d, sport=%u, dip=%d.%d.%d.%d, dport=%u, "
	   "hash_value=%u, add_rule=%d) called\n", rule->rule.vlan_id,
	   rule->rule.proto, ((rule->rule.host4_peer_a >> 24) & 0xff),
	   ((rule->rule.host4_peer_a >> 16) & 0xff),
	   ((rule->rule.host4_peer_a >> 8) & 0xff),
	   ((rule->rule.host4_peer_a >> 0) & 0xff),
	   rule->rule.port_peer_a,
	   ((rule->rule.host4_peer_b >> 24) & 0xff),
	   ((rule->rule.host4_peer_b >> 16) & 0xff),
	   ((rule->rule.host4_peer_b >> 8) & 0xff),
	   ((rule->rule.host4_peer_b >> 0) & 0xff),
	   rule->rule.port_peer_b, hash_value, add_rule);

  if(add_rule) {
    if(pfr->sw_filtering_hash == NULL)
      pfr->sw_filtering_hash = (sw_filtering_hash_bucket **)
	kcalloc(DEFAULT_RING_HASH_SIZE, sizeof(sw_filtering_hash_bucket *), GFP_ATOMIC);
    if(pfr->sw_filtering_hash == NULL) {
      /* kfree(rule); */
      if(enable_debug)
	printk("[PF_RING] handle_sw_filtering_hash_bucket() returned %d [0]\n", -EFAULT);
      return(-EFAULT);
    }
  }

  if(enable_debug)
    printk("[PF_RING] handle_sw_filtering_hash_bucket() allocated memory\n");

  if(pfr->sw_filtering_hash == NULL) {
    /* We're trying to delete a hash rule from an empty hash */
    return(-EFAULT);
  }

  if(pfr->sw_filtering_hash[hash_value] == NULL) {
    if(add_rule)
      pfr->sw_filtering_hash[hash_value] = rule, rule->next = NULL, rc = 0;
    else {
      if(enable_debug)
	printk("[PF_RING] handle_sw_filtering_hash_bucket() returned %d [1]\n", -1);
      return(-1);	/* Unable to find the specified rule */
    }
  } else {
    sw_filtering_hash_bucket *prev = NULL, *bucket = pfr->sw_filtering_hash[hash_value];

    while(bucket != NULL) {
      if(hash_filtering_rule_match(&bucket->rule, &rule->rule)) {
	if(add_rule) {
	  if(enable_debug)
	    printk("[PF_RING] Duplicate found while adding rule: discarded\n");
	  /* kfree(rule); */
	  return(-EEXIST);
	} else {
	  /* We've found the bucket to delete */

	  if(enable_debug)
	    printk("[PF_RING] handle_sw_filtering_hash_bucket()"
		   " found a bucket to delete: removing it\n");
	  if(prev == NULL)
	    pfr->sw_filtering_hash[hash_value] = bucket->next;
	  else
	    prev->next = bucket->next;

	  free_sw_filtering_hash_bucket(bucket);
	  kfree(bucket);
	  if(enable_debug)
	    printk("[PF_RING] handle_sw_filtering_hash_bucket() returned %d [2]\n", 0);
	  return(0);
	}
      } else {
	prev = bucket;
	bucket = bucket->next;
      }
    }

    if(add_rule) {
      /* If the flow arrived until here, then this rule is unique */

      if(enable_debug)
	printk("[PF_RING] handle_sw_filtering_hash_bucket() "
	       "no duplicate rule found: adding the rule\n");

      if(rule->rule.plugin_action.plugin_id > 0) {
	if(plugin_registration[rule->rule.plugin_action.plugin_id]->pfring_plugin_register)
	  plugin_registration[rule->rule.plugin_action.plugin_id]->pfring_plugin_register(0);
      }
      rule->next = pfr->sw_filtering_hash[hash_value];
      pfr->sw_filtering_hash[hash_value] = rule;
      rc = 0;
    } else {
      /* The rule we searched for has not been found */
      rc = -1;
    }
  }

  if(enable_debug)
    printk("[PF_RING] handle_sw_filtering_hash_bucket() returned %d [3]\n",
	   rc);

  return(rc);
}

/* ********************************** */

static int packet_rcv(struct sk_buff *skb, struct net_device *dev,
		      struct packet_type *pt
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16))
		      , struct net_device *orig_dev
#endif
		      )
{
  int rc;

  if(skb->pkt_type != PACKET_LOOPBACK) {
    rc = skb_ring_handler(skb,
			  (skb->pkt_type == PACKET_OUTGOING) ? 0 : 1,
			  1, UNKNOWN_RX_CHANNEL, UNKNOWN_NUM_RX_CHANNELS);

  } else
    rc = 0;

  kfree_skb(skb);
  return(rc);
}

/* ********************************** */

void register_device_handler(void) {
  if(transparent_mode != standard_linux_path) return;

  prot_hook.func = packet_rcv;
  prot_hook.type = htons(ETH_P_ALL);
  dev_add_pack(&prot_hook);
}

/* ********************************** */

void unregister_device_handler(void) {
  if(transparent_mode != standard_linux_path) return;
  dev_remove_pack(&prot_hook); /* Remove protocol hook */
}

/* ********************************** */

static int ring_create(
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24))
		       struct net *net,
#endif
		       struct socket *sock, int protocol
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33))
		       , int kern
#endif
		       )
{
  struct sock *sk;
  struct pf_ring_socket *pfr;
  int err = -ENOMEM;

  if(enable_debug)
    printk("[PF_RING] ring_create()\n");

  /* Are you root, superuser or so ? */
  if(!capable(CAP_NET_ADMIN))
    return -EPERM;

  if(sock->type != SOCK_RAW)
    return -ESOCKTNOSUPPORT;

  if(protocol != htons(ETH_P_ALL))
    return -EPROTONOSUPPORT;

#if(LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,11))
  sk = sk_alloc(PF_RING, GFP_KERNEL, 1, NULL);
#else
#if(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
  // BD: API changed in 2.6.12, ref:
  // http://svn.clkao.org/svnweb/linux/revision/?rev=28201
  sk = sk_alloc(PF_RING, GFP_ATOMIC, &ring_proto, 1);
#else
  sk = sk_alloc(net, PF_INET, GFP_KERNEL, &ring_proto);
#endif
#endif

  if(sk == NULL)
    goto out;

  sock->ops = &ring_ops;
  sock_init_data(sock, sk);
#if(LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,11))
  sk_set_owner(sk, THIS_MODULE);
#endif

  ring_sk(sk) = ring_sk_datatype(kmalloc(sizeof(*pfr), GFP_KERNEL));

  if(!(pfr = ring_sk(sk))) {
    sk_free(sk);
    goto out;
  }

  memset(pfr, 0, sizeof(*pfr));
  pfr->ring_active = 0;	/* We activate as soon as somebody waits for packets */
  pfr->num_rx_channels = UNKNOWN_NUM_RX_CHANNELS;
  pfr->channel_id = RING_ANY_CHANNEL;
  pfr->bucket_len = DEFAULT_BUCKET_LEN;
  pfr->poll_num_pkts_watermark = DEFAULT_MIN_PKT_QUEUED;
  pfr->handle_hash_rule = handle_sw_filtering_hash_bucket;
  pfr->add_packet_to_ring = add_packet_to_ring;
  init_waitqueue_head(&pfr->ring_slots_waitqueue);
  rwlock_init(&pfr->ring_index_lock);
  rwlock_init(&pfr->ring_rules_lock);
  atomic_set(&pfr->num_ring_users, 0);
  INIT_LIST_HEAD(&pfr->sw_filtering_rules);
  INIT_LIST_HEAD(&pfr->hw_filtering_rules);
  sk->sk_family = PF_RING;
  sk->sk_destruct = ring_sock_destruct;

  ring_insert(sk);

  pfr->master_ring = NULL;
  pfr->ring_netdev = &none_device_element; /* Unbound socket */
  pfr->sample_rate = 1;	/* No sampling */
  pfr->ring_id = ring_id_serial++;

  ring_proc_add(pfr);

  if(enable_debug)
    printk("[PF_RING] ring_create(): created\n");

  return(0);
 out:
  return err;
}

/* ************************************* */

static virtual_filtering_device_element* add_virtual_filtering_device(struct sock *sock,
								      virtual_filtering_device_info *info)
{
  virtual_filtering_device_element *elem;

  if(enable_debug)
    printk("[PF_RING] --> add_virtual_filtering_device(%s)\n", info->device_name);

  if(info == NULL)
    return(NULL);

  elem = kmalloc(sizeof(virtual_filtering_device_element), GFP_KERNEL);

  if(elem == NULL)
    return(NULL);
  else {
    memcpy(&elem->info, info, sizeof(virtual_filtering_device_info));
    INIT_LIST_HEAD(&elem->list);
  }

  write_lock_bh(&virtual_filtering_lock);
  list_add(&elem->list, &virtual_filtering_devices_list);  /* Add as first entry */
  write_unlock_bh(&virtual_filtering_lock);

  return(elem);
}

/* ************************************* */

static int remove_virtual_filtering_device(struct sock *sock, char *device_name)
{
  struct list_head *ptr, *tmp_ptr;

  if(enable_debug)
    printk("[PF_RING] --> remove_virtual_filtering_device(%s)\n", device_name);

  write_lock_bh(&virtual_filtering_lock);
  list_for_each_safe(ptr, tmp_ptr, &virtual_filtering_devices_list) {
    virtual_filtering_device_element *filtering_ptr;

    filtering_ptr = list_entry(ptr, virtual_filtering_device_element, list);

    if(strcmp(filtering_ptr->info.device_name, device_name) == 0) {
      list_del(ptr);
      write_unlock_bh(&virtual_filtering_lock);
      kfree(filtering_ptr);
      return(0);
    }
  }

  write_unlock_bh(&virtual_filtering_lock);

  return(-EINVAL);	/* Not found */
}

/* *********************************************** */

static int ring_release(struct socket *sock)
{
  struct sock *sk = sock->sk;
  struct pf_ring_socket *pfr = ring_sk(sk);
  struct list_head *ptr, *tmp_ptr;
  void *ring_memory_ptr;

  if(!sk)
    return 0;
  else
    pfr->ring_active = 0;

  /* Notify the consumer that we're shutting down */
  if(pfr->kernel_consumer_plugin_id
     && plugin_registration[pfr->kernel_consumer_plugin_id]->pfring_packet_term) {
    plugin_registration[pfr->kernel_consumer_plugin_id]->pfring_packet_term(pfr);
  }

  /* Wait until the ring is being used... */
  while(atomic_read(&pfr->num_ring_users) > 0) {
    schedule();
  }

  if(enable_debug)
    printk("[PF_RING] called ring_release(%s)\n", pfr->ring_netdev->dev->name);

  if(pfr->kernel_consumer_options) kfree(pfr->kernel_consumer_options);

  /*
    The calls below must be placed outside the
    write_lock_bh...write_unlock_bh block.
  */
  sock_orphan(sk);
  ring_proc_remove(pfr);
  ring_write_lock();

  if(pfr->ring_netdev->dev && pfr->ring_netdev == &any_device_element)
    num_any_rings--;
  else {
    if(pfr->ring_netdev
       && (pfr->ring_netdev->dev->ifindex < MAX_NUM_IFIDX))
      num_rings_per_device[pfr->ring_netdev->dev->ifindex]--;
  }

  if(pfr->ring_netdev != &none_device_element) {
    if(pfr->cluster_id != 0)
      remove_from_cluster(sk, pfr);
  }

  ring_remove(sk);

  sock->sk = NULL;

  /* Free rules */
  if(pfr->ring_netdev != &none_device_element) {
    list_for_each_safe(ptr, tmp_ptr, &pfr->sw_filtering_rules) {
      sw_filtering_rule_element *rule;
#ifdef CONFIG_TEXTSEARCH
      int i;
#endif

      rule = list_entry(ptr, sw_filtering_rule_element, list);

      if(plugin_registration[rule->rule.plugin_action.plugin_id]
	 && plugin_registration[rule->rule.plugin_action.plugin_id]->pfring_plugin_free_ring_mem) {
	/* Custom free function */
	plugin_registration[rule->rule.plugin_action.plugin_id]->pfring_plugin_free_ring_mem(rule);
      } else {
	if(enable_debug)
	  printk("[PF_RING] --> default_free [rule->rule.plugin_action.plugin_id=%d]\n",
		 rule->rule.plugin_action.plugin_id);
	if(rule->plugin_data_ptr != NULL) {
	  kfree(rule->plugin_data_ptr);
	  rule->plugin_data_ptr = NULL;
	}
      }

#ifdef CONFIG_TEXTSEARCH
      for(i = 0; (i < MAX_NUM_PATTERN) && (rule->pattern[i] != NULL); i++)
	textsearch_destroy(rule->pattern[i]);
#endif

      list_del(ptr);
      free_filtering_rule(&rule->rule);
      kfree(rule);
    }

    /* Filtering hash rules */
    if(pfr->sw_filtering_hash) {
      int i;

      for(i = 0; i < DEFAULT_RING_HASH_SIZE; i++) {
	if(pfr->sw_filtering_hash[i] != NULL) {
	  sw_filtering_hash_bucket *scan = pfr->sw_filtering_hash[i], *next;

	  while(scan != NULL) {
	    next = scan->next;

	    free_sw_filtering_hash_bucket(scan);
	    kfree(scan);
	    scan = next;
	  }
	}
      }

      kfree(pfr->sw_filtering_hash);
    }

    /* printk("[PF_RING] --> num_hw_filtering_rules=%d\n", pfr->num_hw_filtering_rules); */

    /* Free Hw Filtering Rules */
    if(pfr->num_hw_filtering_rules > 0) {
      list_for_each_safe(ptr, tmp_ptr, &pfr->hw_filtering_rules) {
	hw_filtering_rule_element *hw_rule = list_entry(ptr, hw_filtering_rule_element, list);

	/* Remove hw rule */
	handle_hw_filtering_rule(pfr, &hw_rule->rule, remove_hw_rule);

	list_del(ptr);
	kfree(hw_rule);
      }
    }
  }

  if(pfr->dna_device != NULL) {
    dna_device_mapping mapping;

    mapping.operation = remove_device_mapping;
    snprintf(mapping.device_name, sizeof(mapping.device_name)-1,
	     "%s", pfr->ring_netdev->dev->name);
    ring_map_dna_device(pfr, &mapping);
  }

  if(pfr->v_filtering_dev != NULL) {
    remove_virtual_filtering_device(sk, pfr->v_filtering_dev->info.device_name);
    pfr->v_filtering_dev = NULL;
    /* pfr->v_filtering_dev has been freed by remove_virtual_filtering_device() */
  }

  /* Free the ring buffer later, vfree needs interrupts enabled */
  ring_memory_ptr = pfr->ring_memory;
  ring_sk(sk) = NULL;
  skb_queue_purge(&sk->sk_write_queue);

  sock_put(sk);
  ring_write_unlock();

#if(LINUX_VERSION_CODE > KERNEL_VERSION(2,6,32))
  /* Release the vPFRing eventfd */
  if(pfr->vpfring_ctx)
    eventfd_ctx_put(pfr->vpfring_ctx);
#endif

  if(pfr->appl_name != NULL)
    kfree(pfr->appl_name);

  if(ring_memory_ptr != NULL)
    vfree(ring_memory_ptr);

  kfree(pfr);

  if(enable_debug)
    printk("[PF_RING] ring_release: done\n");

  return 0;
}

/* ********************************** */

/*
 * We create a ring for this socket and bind it to the specified device
 */
static int packet_ring_bind(struct sock *sk, char *dev_name)
{
  struct pf_ring_socket *pfr = ring_sk(sk);
  struct list_head *ptr, *tmp_ptr;
  ring_device_element *dev = NULL;

  if(dev_name == NULL)
    return(-EINVAL);

  list_for_each_safe(ptr, tmp_ptr, &ring_aware_device_list) {
    ring_device_element *dev_ptr = list_entry(ptr, ring_device_element, device_list);

    if(strcmp(dev_ptr->dev->name, dev_name) == 0) {
      dev = dev_ptr;
      break;
    }
  }

  if((dev == NULL) || (dev->dev->type != ARPHRD_ETHER))
    return(-EINVAL);


  if(enable_debug)
    printk("[PF_RING] packet_ring_bind(%s, bucket_len=%d) called\n",
	   dev->dev->name, pfr->bucket_len);

  /* Remove old binding (by default binding to none)
     BEFORE binding to a new device
  */
  ring_proc_remove(pfr);

  /*
    IMPORTANT
    Leave this statement here as last one. In fact when
    the ring_netdev != &none_device_element the socket is ready to be used.
  */
  pfr->ring_netdev = dev;

  /* Time to rebind to a new device */
  ring_proc_add(pfr);

  /*
    As the 'struct net_device' does not contain the number
    of RX queues, we can guess that its number is the same as the number
    of TX queues. After the first packet has been received by the adapter
    the num of RX queues is updated with the real value
  */
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31))
  pfr->num_rx_channels = pfr->ring_netdev->dev->real_num_tx_queues;
#else
  pfr->num_rx_channels = 1;
#endif

  if(dev == &any_device_element)
    num_any_rings++;
  else {
    if(dev->dev->ifindex < MAX_NUM_IFIDX)
      num_rings_per_device[dev->dev->ifindex]++;
    else
      printk("[PF_RING] INTERNAL ERROR: ifindex %d for %s is > than MAX_NUM_IFIDX\n",
	     dev->dev->ifindex, dev->dev->name);
  }

  return(0);
}

/* ************************************* */

/* Bind to a device */
static int ring_bind(struct socket *sock, struct sockaddr *sa, int addr_len)
{
  struct sock *sk = sock->sk;

  if(enable_debug)
    printk("[PF_RING] ring_bind() called\n");

  /*
   *      Check legality
   */
  if(addr_len != sizeof(struct sockaddr))
    return -EINVAL;
  if(sa->sa_family != PF_RING)
    return -EINVAL;
  if(sa->sa_data == NULL)
    return -EINVAL;

  /* Safety check: add trailing zero if missing */
  sa->sa_data[sizeof(sa->sa_data) - 1] = '\0';

  if(enable_debug)
    printk("[PF_RING] searching device %s\n", sa->sa_data);

#if 0
  if(strcmp(sa->sa_data, "any") == 0)
    dev = &any_dev;
  else {
    if((dev = __dev_get_by_name(
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24))
				&init_net,
#endif
				sa->sa_data)) == NULL) {

      if(enable_debug)
	printk("[PF_RING] search failed\n");
      return(-EINVAL);
    }
  }
#endif

  return(packet_ring_bind(sk, sa->sa_data));
}

/* ************************************* */

#if(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,11))
/*
 * rvmalloc / rvfree / kvirt_to_pa copied from usbvideo.c
 */
unsigned long kvirt_to_pa(unsigned long adr)
{
  unsigned long kva, ret;

  kva = (unsigned long)page_address(vmalloc_to_page((void *)adr));
  kva |= adr & (PAGE_SIZE - 1);	/* restore the offset */
  ret = __pa(kva);
  return ret;
}
#endif

/* ************************************* */

static int do_memory_mmap(struct vm_area_struct *vma,
			  unsigned long size, char *ptr, u_int flags, int mode)
{
  unsigned long start;

  /* we do not want to have this area swapped out, lock it */
  vma->vm_flags |= flags;

  start = vma->vm_start;

  if(enable_debug)
    printk("[PF_RING] do_memory_mmap(mode=%d, size=%lu, ptr=%p)\n", mode, size, ptr);

  while(size > 0) {
    int rc;

    if(mode == 0) {
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,11))
      rc = remap_vmalloc_range(vma, ptr, 0);
      break; /* Do not iterate */
#else
      rc = remap_pfn_range(vma, start, kvirt_to_pa((unsigned long)ptr), PAGE_SIZE, PAGE_SHARED);
#endif
    } else if(mode == 1) {
      rc = remap_pfn_range(vma, start, __pa(ptr) >> PAGE_SHIFT, PAGE_SIZE, PAGE_SHARED);
    } else {
      rc = remap_pfn_range(vma, start, ((unsigned long)ptr) >> PAGE_SHIFT, PAGE_SIZE, PAGE_SHARED);
    }

    if(rc) {
      if(enable_debug)
	printk("[PF_RING] remap_pfn_range() failed\n");

      return(-EAGAIN);
    }

    start += PAGE_SIZE;
    ptr += PAGE_SIZE;
    if(size > PAGE_SIZE) {
      size -= PAGE_SIZE;
    } else {
      size = 0;
    }
  }

  return(0);
}

/* ************************************* */

static int ring_mmap(struct file *file,
		     struct socket *sock, struct vm_area_struct *vma)
{
  struct sock *sk = sock->sk;
  struct pf_ring_socket *pfr = ring_sk(sk);
  int rc;
  unsigned long size = (unsigned long)(vma->vm_end - vma->vm_start);

  if(enable_debug)
    printk("[PF_RING] ring_mmap() called\n");

  if(ring_alloc_mem(sk) != 0) {
    printk("[PF_RING] ring_mmap(): unable to allocate memory\n");
    return(-EINVAL);
  }

  if(size % PAGE_SIZE) {
    if(enable_debug)
      printk("[PF_RING] ring_mmap() failed: len is not multiple of PAGE_SIZE\n");

    return(-EINVAL);
  }

  if(enable_debug)
    printk("[PF_RING] ring_mmap() called, size: %ld bytes [bucket_len=%d]\n",
	   size, pfr->bucket_len);

  if((pfr->dna_device == NULL) && (pfr->ring_memory == NULL)) {

    if(enable_debug)
      printk("[PF_RING] ring_mmap() failed: "
	     "mapping area to an unbound socket\n");

    return -EINVAL;
  }

  if(pfr->dna_device == NULL) {
    /* if userspace tries to mmap beyond end of our buffer, fail */
    if(size > pfr->slots_info->tot_mem) {

      if(enable_debug)
	printk("[PF_RING] ring_mmap() failed: "
	       "area too large [%ld > %d]\n",
	       size, pfr->slots_info->tot_mem);

      return(-EINVAL);
    }

    if(enable_debug)
      printk("[PF_RING] mmap [slot_len=%d]"
	     "[tot_slots=%d] for ring on device %s\n",
	     pfr->slots_info->slot_len, pfr->slots_info->min_num_slots,
	     pfr->ring_netdev->dev->name);

    if((rc = do_memory_mmap(vma, size, pfr->ring_memory, VM_LOCKED, 0)) < 0)
      return(rc);
  } else {
    int count = pfr->mmap_count;
    /* DNA Device */

    /* printk("[PF_RING] mmap count(%d)\n", count); */

    pfr->mmap_count++;

    switch(count) {
    case 0:
      if((rc = do_memory_mmap(vma, size,
			      (void *)pfr->dna_device->packet_memory, VM_LOCKED, 1)) < 0)
	return(rc);
      break;

    case 1:
      if((rc = do_memory_mmap(vma, size,
			      (void *)pfr->dna_device->descr_packet_memory, VM_LOCKED, 1)) < 0)
	return(rc);
      break;

    case 2:
      if((rc = do_memory_mmap(vma, size,
			      (void *)pfr->dna_device->phys_card_memory, (VM_RESERVED | VM_IO), 2)) < 0)
	return(rc);
      break;

    default:
      return(-EAGAIN);
    }
  }

  if(enable_debug)
    printk("[PF_RING] ring_mmap succeeded\n");

  return 0;
}

/* ************************************* */

static int ring_recvmsg(struct kiocb *iocb, struct socket *sock,
			struct msghdr *msg, size_t len, int flags)
{
  struct pf_ring_socket *pfr = ring_sk(sock->sk);
  u_int32_t queued_pkts, num_loops = 0;

  if(enable_debug)
    printk("[PF_RING] ring_recvmsg called\n");

  pfr->ring_active = 1;

  while((queued_pkts = num_queued_pkts(pfr)) < MIN_QUEUED_PKTS) {
    wait_event_interruptible(pfr->ring_slots_waitqueue, 1);

    if(enable_debug)
      printk("[PF_RING] -> ring_recvmsg "
	     "[queued_pkts=%d][num_loops=%d]\n",
	     queued_pkts, num_loops);

    if(queued_pkts > 0) {
      if(num_loops++ > MAX_QUEUE_LOOPS)
	break;
    }
  }

  return(queued_pkts);
}

/* ************************************* */

/* This code is mostly coming from af_packet.c */
static int ring_sendmsg(struct kiocb *iocb, struct socket *sock,
			struct msghdr *msg, size_t len)
{
  struct pf_ring_socket *pfr = ring_sk(sock->sk);
  struct sockaddr_pkt *saddr=(struct sockaddr_pkt *)msg->msg_name;
  struct sk_buff *skb;
  __be16 proto=0;
  int err = 0;

  /*
   *	Get and verify the address.
   */
  if(saddr)
    {
      if(saddr == NULL) proto = htons(ETH_P_ALL);

      if(msg->msg_namelen < sizeof(struct sockaddr))
	return(-EINVAL);
      if(msg->msg_namelen == sizeof(struct sockaddr_pkt))
	proto = saddr->spkt_protocol;
    }
  else
    return(-ENOTCONN);	/* SOCK_PACKET must be sent giving an address */

  /*
   *	Find the device first to size check it
   */
  if(pfr->ring_netdev->dev == NULL)
    goto out_unlock;

  err = -ENETDOWN;
  if(!(pfr->ring_netdev->dev->flags & IFF_UP))
    goto out_unlock;

  /*
   *	You may not queue a frame bigger than the mtu. This is the lowest level
   *	raw protocol and you must do your own fragmentation at this level.
   */
  err = -EMSGSIZE;
  if(len > pfr->ring_netdev->dev->mtu + pfr->ring_netdev->dev->hard_header_len)
    goto out_unlock;

  err = -ENOBUFS;
  skb = sock_wmalloc(sock->sk, len + LL_RESERVED_SPACE(pfr->ring_netdev->dev), 0, GFP_KERNEL);

  /*
   *	If the write buffer is full, then tough. At this level the user gets to
   *	deal with the problem - do your own algorithmic backoffs. That's far
   *	more flexible.
   */

  if(skb == NULL)
    goto out_unlock;

  /*
   *	Fill it in
   */

  /* FIXME: Save some space for broken drivers that write a
   * hard header at transmission time by themselves. PPP is the
   * notable one here. This should really be fixed at the driver level.
   */
  skb_reserve(skb, LL_RESERVED_SPACE(pfr->ring_netdev->dev));
  skb_reset_network_header(skb);

  /* Try to align data part correctly */
#if(LINUX_VERSION_CODE > KERNEL_VERSION(2,6,23))
  if(pfr->ring_netdev->dev->header_ops) {
    skb->data -= pfr->ring_netdev->dev->hard_header_len;
    skb->tail -= pfr->ring_netdev->dev->hard_header_len;
    if(len < pfr->ring_netdev->dev->hard_header_len)
      skb_reset_network_header(skb);
  }
#else
  if(pfr->ring_netdev->dev->hard_header) {
    skb->data -= pfr->ring_netdev->dev->hard_header_len;
    skb->tail -= pfr->ring_netdev->dev->hard_header_len;
    if(len < pfr->ring_netdev->dev->hard_header_len) {
#if(LINUX_VERSION_CODE > KERNEL_VERSION(2,6,18))
      skb_reset_network_header(skb);
#else
      skb->nh.raw = skb->data;
#endif
    }
  }
#endif

  /* Returns -EFAULT on error */
  err = memcpy_fromiovec(skb_put(skb,len), msg->msg_iov, len);
  skb->protocol = proto;
  skb->dev = pfr->ring_netdev->dev;
  skb->priority = sock->sk->sk_priority;
  if(err)
    goto out_free;

  /*
   *	Now send it
   */

  dev_queue_xmit(skb);
  dev_put(pfr->ring_netdev->dev);
  return(len);

 out_free:
  kfree_skb(skb);

 out_unlock:
  if(pfr->ring_netdev)
    dev_put(pfr->ring_netdev->dev);

  return err;
}

/* ************************************* */

unsigned int ring_poll(struct file *file,
		       struct socket *sock, poll_table * wait)
{
  struct pf_ring_socket *pfr = ring_sk(sock->sk);
  int rc, mask = 0;

  if(enable_debug)
    printk("[PF_RING] -- poll called\n");

  if(pfr->dna_device == NULL) {
    /* PF_RING mode (No DNA) */

    if(enable_debug)
      printk("[PF_RING] poll called (non DNA device)\n");

    pfr->ring_active = 1;
    // smp_rmb();

    //if(pfr->slots_info->tot_read == pfr->slots_info->tot_insert)
    if(num_queued_pkts(pfr) < pfr->poll_num_pkts_watermark)
      poll_wait(file, &pfr->ring_slots_waitqueue, wait);

    if(num_queued_pkts(pfr) >= pfr->poll_num_pkts_watermark)
      mask |= POLLIN | POLLRDNORM;

    return(mask);
  } else {
    /* DNA mode */
    /* enable_debug = 1;  */

    if(enable_debug)
      printk("[PF_RING] poll called on DNA device [%d]\n",
	     *pfr->dna_device->interrupt_received);

    if(pfr->dna_device->wait_packet_function_ptr == NULL) {
      if(enable_debug)
	printk("[PF_RING] wait_packet_function_ptr is NULL: returning to caller\n");

      return(0);
    }

    rc = pfr->dna_device->wait_packet_function_ptr(pfr->dna_device->adapter_ptr, 1);

    if(enable_debug)
      printk("[PF_RING] wait_packet_function_ptr(1) returned %d\n", rc);

    if(rc == 0) {
      if(enable_debug)
	printk("[PF_RING] calling poll_wait()\n");

      /* No packet arrived yet */
      poll_wait(file, pfr->dna_device->packet_waitqueue, wait);

      if(enable_debug)
	printk("[PF_RING] poll_wait() just returned\n");
    } else
      rc = pfr->dna_device->wait_packet_function_ptr(pfr->dna_device->adapter_ptr, 0);

    if(enable_debug)
      printk("[PF_RING] wait_packet_function_ptr(0) returned %d\n", rc);

    //*pfr->dna_device->interrupt_received = rc;
    if(rc == 0)
      rc = *pfr->dna_device->interrupt_received;

    if(enable_debug)
      printk("[PF_RING] poll %s return [%d]\n",
	     pfr->ring_netdev->dev->name,
	     *pfr->dna_device->interrupt_received);

    if(rc) {
      return(POLLIN | POLLRDNORM);
    } else {
      return(0);
    }
  }
}

/* ************************************* */

int add_sock_to_cluster_list(ring_cluster_element * el, struct sock *sock)
{
  if(el->cluster.num_cluster_elements == CLUSTER_LEN)
    return(-1);	/* Cluster full */

  ring_sk_datatype(ring_sk(sock))->cluster_id = el->cluster.cluster_id;
  el->cluster.sk[el->cluster.num_cluster_elements] = sock;
  el->cluster.num_cluster_elements++;
  return(0);
}

/* ************************************* */

int remove_from_cluster_list(struct ring_cluster *el, struct sock *sock)
{
  int i, j;

  for(i = 0; i < CLUSTER_LEN; i++)
    if(el->sk[i] == sock) {
      el->num_cluster_elements--;

      if(el->num_cluster_elements > 0) {
	/* The cluster contains other elements */
	for(j = i; j < CLUSTER_LEN - 1; j++)
	  el->sk[j] = el->sk[j + 1];

	el->sk[CLUSTER_LEN - 1] = NULL;
      } else {
	/* Empty cluster */
	memset(el->sk, 0, sizeof(el->sk));
      }

      return(0);
    }

  return(-1); /* Not found */
}

/* ************************************* */

static int remove_from_cluster(struct sock *sock, struct pf_ring_socket *pfr)
{
  struct list_head *ptr, *tmp_ptr;

  if(enable_debug)
    printk("[PF_RING] --> remove_from_cluster(%d)\n", pfr->cluster_id);

  if(pfr->cluster_id == 0 /* 0 = No Cluster */ )
    return(0);	/* Noting to do */

  list_for_each_safe(ptr, tmp_ptr, &ring_cluster_list) {
    ring_cluster_element *cluster_ptr;

    cluster_ptr = list_entry(ptr, ring_cluster_element, list);

    if(cluster_ptr->cluster.cluster_id == pfr->cluster_id) {
      return(remove_from_cluster_list(&cluster_ptr->cluster, sock));
    }
  }

  return(-EINVAL);	/* Not found */
}

/* ************************************* */

static int set_master_ring(struct sock *sock,
			   struct pf_ring_socket *pfr,
			   u_int32_t master_socket_id)
{
  int rc = -1;
  struct list_head *ptr;

  if(enable_debug)
    printk("[PF_RING] set_master_ring(%s=%d)\n",
	   pfr->ring_netdev->dev ? pfr->ring_netdev->dev->name : "none",
	   master_socket_id);

  /* Avoid the ring to be manipulated while playing with it */
  ring_read_lock();

  list_for_each(ptr, &ring_table) {
    struct pf_ring_socket *sk_pfr;
    struct ring_element *entry;
    struct sock *skElement;

    entry = list_entry(ptr, struct ring_element, list);

    skElement = entry->sk;
    sk_pfr = ring_sk(skElement);

    if((sk_pfr != NULL) && (sk_pfr->ring_id == master_socket_id)) {
      pfr->master_ring = sk_pfr;

      if(enable_debug)
	printk("[PF_RING] Found set_master_ring(%s) -> %s\n",
	       sk_pfr->ring_netdev->dev ? sk_pfr->ring_netdev->dev->name : "none",
	       pfr->master_ring->ring_netdev->dev->name);

      rc = 0;
      break;
    } else {
      if(enable_debug)
	printk("[PF_RING] Skipping socket(%s)=%d\n",
	       sk_pfr->ring_netdev->dev ? sk_pfr->ring_netdev->dev->name : "none",
	       sk_pfr->ring_id);
    }
  }

  ring_read_unlock();

  if(enable_debug)
    printk("[PF_RING] set_master_ring(%s, socket_id=%d) = %d\n",
	   pfr->ring_netdev->dev ? pfr->ring_netdev->dev->name : "none",
	   master_socket_id, rc);

  return(rc);
}

/* ************************************* */

static int add_sock_to_cluster(struct sock *sock,
			       struct pf_ring_socket *pfr,
			       struct add_to_cluster *cluster)
{
  struct list_head *ptr, *tmp_ptr;
  ring_cluster_element *cluster_ptr;

  if(enable_debug)
    printk("[PF_RING] --> add_sock_to_cluster(%d)\n", cluster->clusterId);

  if(cluster->clusterId == 0 /* 0 = No Cluster */ )
    return(-EINVAL);

  if(pfr->cluster_id != 0)
    remove_from_cluster(sock, pfr);

  list_for_each_safe(ptr, tmp_ptr, &ring_cluster_list) {
    cluster_ptr = list_entry(ptr, ring_cluster_element, list);

    if(cluster_ptr->cluster.cluster_id == cluster->clusterId) {
      return(add_sock_to_cluster_list(cluster_ptr, sock));
    }
  }

  /* There's no existing cluster. We need to create one */
  if((cluster_ptr = kmalloc(sizeof(ring_cluster_element), GFP_KERNEL)) == NULL)
    return(-ENOMEM);

  INIT_LIST_HEAD(&cluster_ptr->list);

  cluster_ptr->cluster.cluster_id = cluster->clusterId;
  cluster_ptr->cluster.num_cluster_elements = 1;
  cluster_ptr->cluster.hashing_mode = cluster->the_type; /* Default */
  cluster_ptr->cluster.hashing_id = 0;

  memset(cluster_ptr->cluster.sk, 0, sizeof(cluster_ptr->cluster.sk));
  cluster_ptr->cluster.sk[0] = sock;
  pfr->cluster_id = cluster->clusterId;
  list_add(&cluster_ptr->list, &ring_cluster_list); /* Add as first entry */

  return(0); /* 0 = OK */
}

/* ************************************* */

static int ring_map_dna_device(struct pf_ring_socket *pfr,
			       dna_device_mapping * mapping)
{
  if(mapping->operation == remove_device_mapping) {

    /* Unlock driver */
    if(pfr->dna_device != NULL)
      pfr->dna_device->usage_notification(pfr->dna_device->adapter_ptr, 0 /* unlock */);

    pfr->dna_device = NULL;
    if(enable_debug)
      printk("[PF_RING] ring_map_dna_device(%s): removed mapping\n",
	     mapping->device_name);
    return(0);
  } else {
    struct list_head *ptr, *tmp_ptr;
    dna_device_list *entry;

    ring_proc_remove(pfr);

    list_for_each_safe(ptr, tmp_ptr, &ring_dna_devices_list) {
      entry = list_entry(ptr, dna_device_list, list);

      if((!strcmp(entry->dev.netdev->name, mapping->device_name))
	 && (entry->dev.channel_id == mapping->channel_id)) {
	pfr->dna_device = &entry->dev, pfr->ring_netdev->dev = entry->dev.netdev;

	if(enable_debug)
	  printk("[PF_RING] ring_map_dna_device(%s, %u): added mapping\n",
		 mapping->device_name, mapping->channel_id);

	/* Lock driver */
	pfr->dna_device->usage_notification(pfr->dna_device->adapter_ptr, 1 /* lock */);
	ring_proc_add(pfr);
	return(0);
      }
    }
  }

  printk("[PF_RING] ring_map_dna_device(%s, %u): mapping failed\n",
	 mapping->device_name, mapping->channel_id);

  return(-1);
}

/* ************************************* */

static void purge_idle_hash_rules(struct pf_ring_socket *pfr,
				  uint16_t rule_inactivity)
{
  int i, num_purged_rules = 0;
  unsigned long expire_jiffies =
    jiffies - msecs_to_jiffies(1000 * rule_inactivity);

  if(enable_debug)
    printk("[PF_RING] purge_idle_hash_rules(rule_inactivity=%d)\n",
	   rule_inactivity);

  /* Free filtering hash rules inactive for more than rule_inactivity seconds */
  if(pfr->sw_filtering_hash != NULL) {
    for(i = 0; i < DEFAULT_RING_HASH_SIZE; i++) {
      if(pfr->sw_filtering_hash[i] != NULL) {
	sw_filtering_hash_bucket *scan = pfr->sw_filtering_hash[i], *next, *prev = NULL;

	while(scan != NULL) {
	  next = scan->next;

	  if(scan->rule.internals.jiffies_last_match < expire_jiffies) {
	    /* Expired rule: free it */

	    if(enable_debug)
	      printk ("[PF_RING] Purging hash rule "
		      /* "[last_match=%u][expire_jiffies=%u]" */
		      "[%d.%d.%d.%d:%d <-> %d.%d.%d.%d:%d][purged=%d][tot_rules=%d]\n",
		      /*
			(unsigned int)scan->rule.internals.jiffies_last_match,
			(unsigned int)expire_jiffies,
		      */
		      ((scan->rule.host4_peer_a >> 24) & 0xff),
		      ((scan->rule.host4_peer_a >> 16) & 0xff),
		      ((scan->rule.host4_peer_a >> 8)  & 0xff),
		      ((scan->rule.host4_peer_a >> 0)  & 0xff),
		      scan->rule.port_peer_a,
		      ((scan->rule.host4_peer_b >> 24) & 0xff),
		      ((scan->rule.host4_peer_b >> 16) & 0xff),
		      ((scan->rule.host4_peer_b >> 8)  & 0xff),
		      ((scan->rule.host4_peer_b >> 0) & 0xff),
		      scan->rule.port_peer_b,
		      num_purged_rules,
		      pfr->num_sw_filtering_rules);

	    free_sw_filtering_hash_bucket
	      (scan);
	    kfree(scan);

	    if(prev == NULL)
	      pfr->sw_filtering_hash[i] = next;
	    else
	      prev->next = next;

	    pfr->num_sw_filtering_rules--,
	      num_purged_rules++;
	  } else
	    prev = scan;

	  scan = next;
	}
      }
    }
  }

  if(enable_debug)
    printk("[PF_RING] Purged %d hash rules [tot_rules=%d]\n",
	   num_purged_rules, pfr->num_sw_filtering_rules);
}

/* ************************************* */

static int remove_sw_filtering_rule_element(struct pf_ring_socket *pfr, u_int16_t rule_id)
{
  int rule_found = 0;
  struct list_head *ptr, *tmp_ptr;

  write_lock(&pfr->ring_rules_lock);

  list_for_each_safe(ptr, tmp_ptr, &pfr->sw_filtering_rules) {
    sw_filtering_rule_element *entry;

    entry = list_entry(ptr, sw_filtering_rule_element, list);

    if(entry->rule.rule_id == rule_id) {
#ifdef CONFIG_TEXTSEARCH
      int i;

      for(i = 0; (i < MAX_NUM_PATTERN) && (entry->pattern[i] != NULL); i++)
	textsearch_destroy(entry->pattern[i]);
#endif
      list_del(ptr);
      pfr->num_sw_filtering_rules--;

      if(entry->plugin_data_ptr)
	kfree(entry->plugin_data_ptr);
      free_filtering_rule(&entry->rule);
      kfree(entry);
      if(enable_debug)
	printk("[PF_RING] SO_REMOVE_FILTERING_RULE: rule %d has been removed\n", rule_id);
      rule_found = 1;
      break;
    }
  }	/* for */

  write_unlock(&pfr->ring_rules_lock);

  return(rule_found);
}

/* ************************************* */

static int add_sw_filtering_rule_element(struct pf_ring_socket *pfr, sw_filtering_rule_element *rule)
{
  struct list_head *ptr, *tmp_ptr;
  int idx = 0;
  sw_filtering_rule_element *entry;
  struct list_head *prev = NULL;

  /* Rule checks */
  if(rule->rule.extended_fields.filter_plugin_id > 0) {
    int ret = 0;

    if(rule->rule.extended_fields.filter_plugin_id >= MAX_PLUGIN_ID)
      ret = -EFAULT;
    else if(plugin_registration[rule->rule.extended_fields.filter_plugin_id] == NULL)
      ret = -EFAULT;

    if(ret != 0) {
      if(enable_debug)
	printk("[PF_RING] Invalid filtering plugin [id=%d]\n",
	       rule->rule.extended_fields.filter_plugin_id);
      kfree(rule);
      return(ret);
    }
  }

  if(rule->rule.plugin_action.plugin_id != NO_PLUGIN_ID) {
    int ret = 0;

    if(rule->rule.plugin_action.plugin_id >= MAX_PLUGIN_ID)
      ret = -EFAULT;
    else if(plugin_registration[rule->rule.plugin_action.plugin_id] == NULL)
      ret = -EFAULT;

    if(ret != 0) {
      if(enable_debug)
	printk("[PF_RING] Invalid action plugin [id=%d]\n",
	       rule->rule.plugin_action.plugin_id);
      kfree(rule);
      return(ret);
    }
  }

  if(rule->rule.reflector_device_name[0] != '\0') {
    if((pfr->ring_netdev->dev != NULL)
       && (strcmp(rule->rule.reflector_device_name, pfr->ring_netdev->dev->name) == 0)) {
      if(enable_debug)
	printk("[PF_RING] You cannot use as reflection device the same device on which this ring is bound\n");
      kfree(rule);
      return(-EFAULT);
    }

    rule->rule.internals.reflector_dev = dev_get_by_name(
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24))
							 &init_net,
#endif
							 rule->rule.reflector_device_name);

    if(rule->rule.internals.reflector_dev == NULL) {
      printk("[PF_RING] Unable to find device %s\n", rule->rule.reflector_device_name);
      kfree(rule);
      return(-EFAULT);
    }
  } else
    rule->rule.internals.reflector_dev = NULL;

  /* Compile pattern if present */
  if(strlen(rule->rule.extended_fields.payload_pattern) > 0) {
    char *pattern = rule->rule.extended_fields.payload_pattern;

    printk("[PF_RING] About to compile pattern '%s'\n", pattern);

    while(pattern && (idx < MAX_NUM_PATTERN)) {
      char *pipe = strchr(pattern, '|');

      if(pipe)
	pipe[0] = '\0';

#ifdef CONFIG_TEXTSEARCH
      rule->pattern[idx] = textsearch_prepare("bm"	/* Boyer-Moore */
					      /* "kmp" = Knuth-Morris-Pratt */
					      , pattern, strlen(pattern),
					      GFP_KERNEL,
					      TS_AUTOLOAD
#ifdef TS_IGNORECASE
					      | TS_IGNORECASE
#endif
					      );
      if(rule->pattern[idx])
	printk("[PF_RING] Compiled pattern '%s' [idx=%d]\n", pattern, idx);
#endif
      if(pipe)
	pattern = &pipe[1], idx++;
      else
	break;
    }
  } else {
#ifdef CONFIG_TEXTSEARCH
    rule->pattern[0] = NULL;
#endif
  }

  if(enable_debug)
    printk("[PF_RING] SO_ADD_FILTERING_RULE: About to add rule %d\n",
	   rule->rule.rule_id);

  /* Implement an ordered add */
  list_for_each_safe(ptr, tmp_ptr, &pfr->sw_filtering_rules) {
    entry = list_entry(ptr, sw_filtering_rule_element, list);

    if(enable_debug)
      printk("[PF_RING] SO_ADD_FILTERING_RULE: [current rule %d][rule to add %d]\n",
	     entry->rule.rule_id,
	     rule->rule.rule_id);

    if(entry->rule.rule_id > rule->rule.rule_id) {
      if(prev == NULL) {
	list_add(&rule->list, &pfr->sw_filtering_rules);	/* Add as first entry */
	pfr->num_sw_filtering_rules++;
	if(enable_debug)
	  printk("[PF_RING] SO_ADD_FILTERING_RULE: added rule %d as head rule\n",
		 rule->rule.rule_id);
      } else {
	list_add(&rule->list, prev);
	pfr->num_sw_filtering_rules++;
	if(enable_debug)
	  printk("[PF_RING] SO_ADD_FILTERING_RULE: added rule %d\n",
		 rule->rule.rule_id);
      }

      rule = NULL;
      break;
    } else
      prev = ptr;
  }	/* for */

  if(rule != NULL) {
    if(prev == NULL) {
      list_add(&rule->list, &pfr->sw_filtering_rules);	/* Add as first entry */
      pfr->num_sw_filtering_rules++;
      if(enable_debug)
	printk("[PF_RING] SO_ADD_FILTERING_RULE: added rule %d as first rule\n",
	       rule->rule.rule_id);
    } else {
      list_add_tail(&rule->list, &pfr->sw_filtering_rules);	/* Add as first entry */
      pfr->num_sw_filtering_rules++;
      if(enable_debug)
	printk("[PF_RING] SO_ADD_FILTERING_RULE: added rule %d as last rule\n",
	       rule->rule.rule_id);
    }
  }

  if(rule->rule.extended_fields.filter_plugin_id > 0) {
    if(plugin_registration[rule->rule.extended_fields.filter_plugin_id]->pfring_plugin_register)
      plugin_registration[rule->rule.extended_fields.filter_plugin_id]->pfring_plugin_register(1);
  }

  if(rule->rule.plugin_action.plugin_id > 0) {
    if(plugin_registration[rule->rule.plugin_action.plugin_id]->pfring_plugin_register)
      plugin_registration[rule->rule.plugin_action.plugin_id]->pfring_plugin_register(1);
  }

  return(0);
}

/* ************************************* */

static int add_sw_filtering_hash_bucket(struct pf_ring_socket *pfr, sw_filtering_hash_bucket *rule) {
  int rc = 0;

  if(rule->rule.reflector_device_name[0] != '\0') {
    if((pfr->ring_netdev->dev != NULL)
       && (strcmp(rule->rule.reflector_device_name, pfr->ring_netdev->dev->name) == 0)) {
      if(enable_debug)
	printk("[PF_RING] You cannot use as reflection device the same device on "
	       "which this ring is bound\n");
      kfree(rule);
      return(-EFAULT);
    }

    rule->rule.internals.reflector_dev = dev_get_by_name(
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24))
							 &init_net,
#endif
							 rule->rule.reflector_device_name);

    if(rule->rule.internals.reflector_dev == NULL) {
      printk("[PF_RING] Unable to find device %s\n",
	     rule->rule.reflector_device_name);
      kfree(rule);
      return(-EFAULT);
    }
  } else
    rule->rule.internals.reflector_dev = NULL;

  write_lock(&pfr->ring_rules_lock);
  rc = handle_sw_filtering_hash_bucket(pfr, rule, 1 /* add */);

  if((rc != 0) && (rc != -EEXIST)) {
    kfree(rule);
  } else {
    if(rc != -EEXIST)
      pfr->num_sw_filtering_rules++;
  }

  write_unlock(&pfr->ring_rules_lock);
  return(rc);
}

/* ************************************* */

/* Code taken/inspired from core/sock.c */
static int ring_setsockopt(struct socket *sock,
			   int level, int optname,
			   char __user * optval,
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31))
			   unsigned
#endif
			   int optlen)
{
  struct pf_ring_socket *pfr = ring_sk(sock->sk);
  int val, found, ret = 0 /* OK */;
  u_int32_t ring_id;
  struct add_to_cluster cluster;
  int32_t channel_id;
  char applName[32 + 1] = { 0 };
  u_int16_t rule_id, rule_inactivity;
  packet_direction direction;
  hw_filtering_rule hw_rule;
  struct list_head *ptr, *tmp_ptr;
#if(LINUX_VERSION_CODE > KERNEL_VERSION(2,6,32))
  struct vpfring_eventfd_info eventfd_i;
  struct file *eventfp;
#endif

  if(pfr == NULL)
    return(-EINVAL);

  if(get_user(val, (int *)optval))
    return -EFAULT;

  found = 1;

  switch(optname) {
  case SO_ATTACH_FILTER:
    ret = -EINVAL;

    if(enable_debug)
      printk("[PF_RING] BPF filter (%d)\n", 0);

    if(optlen == sizeof(struct sock_fprog)) {
      unsigned int fsize;
      struct sock_fprog fprog;
      struct sk_filter *filter;

      ret = -EFAULT;

      if(enable_debug)
	printk("[PF_RING] BPF filter (%d)\n", 1);

      /*
	NOTE

	Do not call copy_from_user within a held
	splinlock (e.g. ring_mgmt_lock) as this caused
	problems when certain debugging was enabled under
	2.6.5 -- including hard lockups of the machine.
      */
      if(copy_from_user(&fprog, optval, sizeof(fprog)))
	break;

      /* Fix below courtesy of Noam Dev <noamdev@gmail.com> */
      fsize  = sizeof(struct sock_filter) * fprog.len;
      filter = kmalloc(fsize + sizeof(struct sk_filter), GFP_KERNEL);

      if(filter == NULL) {
	ret = -ENOMEM;
	break;
      }

      if(copy_from_user(filter->insns, fprog.filter, fsize))
	break;

      filter->len = fprog.len;

      if(sk_chk_filter(filter->insns, filter->len) != 0) {
	/* Bad filter specified */
	kfree(filter);
	pfr->bpfFilter = NULL;
	break;
      }

      /* get the lock, set the filter, release the lock */
      write_lock(&pfr->ring_rules_lock);
      pfr->bpfFilter = filter;
      write_unlock(&pfr->ring_rules_lock);
      ret = 0;

      if(enable_debug)
	printk("[PF_RING] BPF filter attached successfully [len=%d]\n",
	       filter->len);
    }
    break;

  case SO_DETACH_FILTER:
    write_lock(&pfr->ring_rules_lock);
    found = 1;
    if(pfr->bpfFilter != NULL) {
      kfree(pfr->bpfFilter);
      pfr->bpfFilter = NULL;
    } else
      ret = -ENONET;
    write_unlock(&pfr->ring_rules_lock);
    break;

  case SO_ADD_TO_CLUSTER:
    if(optlen != sizeof(cluster))
      return -EINVAL;

    if(copy_from_user(&cluster, optval, sizeof(cluster)))
      return -EFAULT;

    write_lock(&pfr->ring_rules_lock);
    ret = add_sock_to_cluster(sock->sk, pfr, &cluster);
    write_unlock(&pfr->ring_rules_lock);
    break;

  case SO_REMOVE_FROM_CLUSTER:
    write_lock(&pfr->ring_rules_lock);
    ret = remove_from_cluster(sock->sk, pfr);
    write_unlock(&pfr->ring_rules_lock);
    break;

  case SO_SET_CHANNEL_ID:
    if(optlen != sizeof(channel_id))
      return -EINVAL;

    if(copy_from_user(&channel_id, optval, sizeof(channel_id)))
      return -EFAULT;

    pfr->channel_id = channel_id;
    if(enable_debug)
      printk("[PF_RING] [pfr->channel_id=%d][channel_id=%d]\n",
	     pfr->channel_id, channel_id);

    ret = 0;
    break;

  case SO_SET_APPL_NAME:
    if(optlen >
       sizeof(applName) /* Names should not be too long */ )
      return -EINVAL;

    if(copy_from_user(&applName, optval, optlen))
      return -EFAULT;

    if(pfr->appl_name != NULL)
      kfree(pfr->appl_name);
    pfr->appl_name = (char *)kmalloc(optlen + 1, GFP_ATOMIC);
    if(pfr->appl_name != NULL) {
      memcpy(pfr->appl_name, applName, optlen);
      pfr->appl_name[optlen] = '\0';
    }

    ret = 0;
    break;

  case SO_SET_PACKET_DIRECTION:
    if(optlen != sizeof(direction))
      return -EINVAL;

    if(copy_from_user(&direction, optval, sizeof(direction)))
      return -EFAULT;

    pfr->direction = direction;
    if(enable_debug)
      printk("[PF_RING] [pfr->direction=%d][direction=%d]\n",
	     pfr->direction, direction);

    ret = 0;
    break;

  case SO_PURGE_IDLE_HASH_RULES:
    if(optlen != sizeof(rule_inactivity))
      return -EINVAL;

    if(copy_from_user(&rule_inactivity, optval, sizeof(rule_inactivity)))
      return -EFAULT;
    else {
      if(rule_inactivity > 0) {
	write_lock(&pfr->ring_rules_lock);
	purge_idle_hash_rules(pfr, rule_inactivity);
	write_unlock(&pfr->ring_rules_lock);
      }
      ret = 0;
    }
    break;

  case SO_TOGGLE_FILTER_POLICY:
    if(optlen != sizeof(u_int8_t))
      return -EINVAL;
    else {
      u_int8_t new_policy;

      if(copy_from_user(&new_policy, optval, optlen))
	return -EFAULT;

      write_lock(&pfr->ring_rules_lock);
      pfr->sw_filtering_rules_default_accept_policy = new_policy;
      write_unlock(&pfr->ring_rules_lock);
      /*
	if(enable_debug)
	printk("[PF_RING] SO_TOGGLE_FILTER_POLICY: default policy is %s\n",
	pfr->sw_filtering_rules_default_accept_policy ? "accept" : "drop");
      */
    }
    break;

  case SO_ADD_FILTERING_RULE:
    if(enable_debug)
      printk("[PF_RING] +++ SO_ADD_FILTERING_RULE(len=%d)(len=%u)\n",
	     optlen, (unsigned int)sizeof(ip_addr));

    if(pfr->ring_netdev == &none_device_element)
      return -EFAULT;

    if(optlen == sizeof(filtering_rule)) {
      int ret;
      sw_filtering_rule_element *rule;
      struct list_head *ptr, *tmp_ptr;

      if(enable_debug)
	printk("[PF_RING] Allocating memory [filtering_rule]\n");

      rule =(sw_filtering_rule_element *)
	kcalloc(1, sizeof(sw_filtering_rule_element), GFP_KERNEL);

      if(rule == NULL)
	return -EFAULT;

      if(copy_from_user(&rule->rule, optval, optlen))
	return -EFAULT;

      INIT_LIST_HEAD(&rule->list);

      write_lock(&pfr->ring_rules_lock);
      list_for_each_safe(ptr, tmp_ptr, &pfr->sw_filtering_rules) {
	sw_filtering_rule_element *entry;

	entry = list_entry(ptr, sw_filtering_rule_element, list);

	if(entry->rule.rule_id == rule_id) {
	  /* A rule with the same if exists */
	  write_unlock(&pfr->ring_rules_lock);
	  return(-EEXIST);
	}
      }

      ret = add_sw_filtering_rule_element(pfr, rule);
      write_unlock(&pfr->ring_rules_lock);

      if(ret != 0) return(ret);
    } else if(optlen == sizeof(hash_filtering_rule)) {
      /* This is a hash rule */
      sw_filtering_hash_bucket *rule =
	(sw_filtering_hash_bucket *) kcalloc(1,
					     sizeof(sw_filtering_hash_bucket),
					     GFP_KERNEL);
      int ret;

      if(rule == NULL)
	return -EFAULT;

      if(copy_from_user(&rule->rule, optval, optlen))
	return -EFAULT;

      ret = add_sw_filtering_hash_bucket(pfr, rule);

      if(ret != 0) return(ret);
    } else {
      printk("[PF_RING] Bad rule length (%d): discarded\n", optlen);
      return -EFAULT;
    }
    break;

  case SO_REMOVE_FILTERING_RULE:
    if(pfr->ring_netdev == &none_device_element) return -EFAULT;

    if(optlen == sizeof(u_int16_t /* rule_id */ )) {
      /* This is a list rule */
      if(copy_from_user(&rule_id, optval, optlen))
	return -EFAULT;

      if(remove_sw_filtering_rule_element(pfr, rule_id) == 0) {
	if(enable_debug)
	  printk("[PF_RING] SO_REMOVE_FILTERING_RULE: rule %d does not exist\n", rule_id);
	return -EFAULT;	/* Rule not found */
      }
    } else if(optlen == sizeof(hash_filtering_rule)) {
      /* This is a hash rule */
      sw_filtering_hash_bucket rule;
      int rc;

      if(copy_from_user(&rule.rule, optval, optlen))
	return -EFAULT;

      write_lock(&pfr->ring_rules_lock);
      rc = handle_sw_filtering_hash_bucket(pfr, &rule, 0 /* delete */ );

      if(rc != 0) {
	write_unlock(&pfr->ring_rules_lock);
	return(rc);
      } else {
	pfr->num_sw_filtering_rules--;
	write_unlock(&pfr->ring_rules_lock);
      }
    } else
      return -EFAULT;
    break;

  case SO_SET_SAMPLING_RATE:
    if(optlen != sizeof(pfr->sample_rate))
      return -EINVAL;

    if(copy_from_user
       (&pfr->sample_rate, optval, sizeof(pfr->sample_rate)))
      return -EFAULT;
    break;

  case SO_ACTIVATE_RING:
    if(enable_debug)
      printk("[PF_RING] * SO_ACTIVATE_RING *\n");
    found = 1, pfr->ring_active = 1;
    break;

  case SO_DEACTIVATE_RING:
    if(enable_debug)
      printk("[PF_RING] * SO_DEACTIVATE_RING *\n");
    found = 1, pfr->ring_active = 0;
    break;

  case SO_SET_POLL_WATERMARK:
    if(optlen != sizeof(u_int16_t))
      return -EINVAL;
    else {
      u_int16_t threshold =  pfr->slots_info->min_num_slots/2;

      if(copy_from_user(&pfr->poll_num_pkts_watermark, optval, optlen))
	return -EFAULT;

      if(pfr->poll_num_pkts_watermark > threshold)
	pfr->poll_num_pkts_watermark = threshold;

      if(pfr->poll_num_pkts_watermark == 0)
	pfr->poll_num_pkts_watermark = 1;

      if(enable_debug)
	printk("[PF_RING] --> SO_SET_POLL_WATERMARK=%d\n", pfr->poll_num_pkts_watermark);
    }
    break;

  case SO_RING_BUCKET_LEN:
    if(optlen != sizeof(u_int32_t))
      return -EINVAL;
    else {
      if(copy_from_user(&pfr->bucket_len, optval, optlen))
	return -EFAULT;

      if(enable_debug)
	printk("[PF_RING] --> SO_RING_BUCKET_LEN=%d\n", pfr->bucket_len);
    }
    break;

  case SO_MAP_DNA_DEVICE:
    if(optlen != sizeof(dna_device_mapping))
      return -EINVAL;
    else {
      dna_device_mapping mapping;

      if(copy_from_user(&mapping, optval, optlen))
	return -EFAULT;
      else
	ret = ring_map_dna_device(pfr, &mapping), found = 1;
    }
    break;

  case SO_SET_MASTER_RING:
    /* Avoid using master sockets with bound rings */
    if(pfr->ring_netdev == &none_device_element) return -EFAULT;

    if(optlen != sizeof(ring_id))
      return -EINVAL;

    if(copy_from_user(&ring_id, optval, sizeof(ring_id)))
      return -EFAULT;

    write_lock(&pfr->ring_rules_lock);
    ret = set_master_ring(sock->sk, pfr, ring_id);
    write_unlock(&pfr->ring_rules_lock);
    break;

  case SO_ADD_HW_FILTERING_RULE:
    if(optlen != sizeof(hw_filtering_rule))
      return -EINVAL;

    if(copy_from_user(&hw_rule, optval, sizeof(hw_rule)))
      return -EFAULT;

    /* Check if a rule with the same id exists */
    list_for_each_safe(ptr, tmp_ptr, &pfr->hw_filtering_rules) {
      hw_filtering_rule_element *rule = list_entry(ptr, hw_filtering_rule_element, list);

      if(rule->rule.rule_id == hw_rule.rule_id) {
	/* There's already a rule with the same id: failure */
	return -EINVAL;
      }
    }

    ret = handle_hw_filtering_rule(pfr, &hw_rule, add_hw_rule);

    if(ret != -1) {
      hw_filtering_rule_element *rule;

      /* Add the hw rule to the socket hw rule list */
      rule = kmalloc(sizeof(hw_filtering_rule_element), GFP_ATOMIC);
      if(rule != NULL) {
	INIT_LIST_HEAD(&rule->list);
	memcpy(&rule->rule, &hw_rule, sizeof(hw_rule));
	list_add(&rule->list, &pfr->hw_filtering_rules); /* Add as first entry */
	pfr->num_hw_filtering_rules++;
      } else
	printk("[PF_RING] Out of memory\n");

      /* Increase the number of device hw rules */
      list_for_each_safe(ptr, tmp_ptr, &ring_aware_device_list) {
        ring_device_element *dev_ptr = list_entry(ptr, ring_device_element, device_list);

        if(dev_ptr->dev == pfr->ring_netdev->dev) {
	  dev_ptr->hw_filters.num_filters++;
          break;
        }
      }
    }
    break;

  case SO_DEL_HW_FILTERING_RULE:
    if(optlen != sizeof(u_int16_t))
      return -EINVAL;

    if(copy_from_user(&rule_id, optval, sizeof(u_int16_t)))
      return -EFAULT;

    /* Check if the rule we want to remove exists */
    found = 0;
    list_for_each_safe(ptr, tmp_ptr, &pfr->hw_filtering_rules) {
      hw_filtering_rule_element *rule = list_entry(ptr, hw_filtering_rule_element, list);

      if(rule->rule.rule_id == rule_id) {
	/* There's already a rule with the same id: good */
	memcpy(&hw_rule, &rule->rule, sizeof(hw_filtering_rule));
	list_del(ptr);
        kfree(rule);
	found = 1;
	break;
      }
    }

    if(!found) return -EINVAL;

    ret = handle_hw_filtering_rule(pfr, &hw_rule, remove_hw_rule);

    if(ret != -1) {
      struct list_head *ptr, *tmp_ptr;

      pfr->num_hw_filtering_rules--;

      list_for_each_safe(ptr, tmp_ptr, &ring_aware_device_list) {
        ring_device_element *dev_ptr = list_entry(ptr, ring_device_element, device_list);

        if(dev_ptr->dev == pfr->ring_netdev->dev) {
	  if(dev_ptr->hw_filters.num_filters > 0)
	    dev_ptr->hw_filters.num_filters--;
          break;
        }
      }
    }
    break;

  case SO_SET_PACKET_CONSUMER_MODE:
    {
      u_int diff = optlen-sizeof(pfr->kernel_consumer_plugin_id);

      /* Copy the pluginId */
      if(copy_from_user(&pfr->kernel_consumer_plugin_id, optval,
			sizeof(pfr->kernel_consumer_plugin_id)))
	return -EFAULT;

#if 0
      printk("[PF_RING] SO_SET_PACKET_CONSUMER_MODE=%d [diff=%d]\n",
	     pfr->kernel_consumer_plugin_id, diff);
#endif

      if(diff > 0) {
	pfr->kernel_consumer_options = kmalloc(diff, GFP_KERNEL);

	if(pfr->kernel_consumer_options != NULL) {
	  if(copy_from_user(pfr->kernel_consumer_options,
			    &optval[sizeof(pfr->kernel_consumer_plugin_id)], diff))
	    return -EFAULT;
	} else
	  return -EFAULT;
      }

      /* Notify the consumer that we're ready to start */
      if(pfr->kernel_consumer_plugin_id
	 && (plugin_registration[pfr->kernel_consumer_plugin_id] == NULL)) {
	if(enable_debug)
	  printk("[PF_RING] Plugin %d is unknown\n", pfr->kernel_consumer_plugin_id);

	pfr->kernel_consumer_plugin_id = 0;
	if(pfr->kernel_consumer_options != NULL) {
	  kfree(pfr->kernel_consumer_options);
	  pfr->kernel_consumer_options = NULL;
	}

	return -EFAULT;
      } else {
	if(plugin_registration[pfr->kernel_consumer_plugin_id]->pfring_packet_start
	   && (!pfr->ring_active)) {
	  plugin_registration[pfr->kernel_consumer_plugin_id]->
	    pfring_packet_start(pfr, copy_raw_data_to_ring);
	}
      }
    }
    break;

#if(LINUX_VERSION_CODE > KERNEL_VERSION(2,6,32))
  case SO_SET_VPFRING_EVENTFD:
    if(optlen != sizeof(eventfd_i))
      return -EINVAL;

    if(copy_from_user(&eventfd_i, optval, sizeof(eventfd_i)))
      return -EFAULT;

    if(IS_ERR(eventfp = eventfd_fget(eventfd_i.fd))) {
      return -EFAULT;
    }

    pfr->vpfring_ctx = eventfd_ctx_fileget(eventfp);
    break;
#endif

  case SO_SET_VIRTUAL_FILTERING_DEVICE:
    {
      virtual_filtering_device_info elem;

      if(optlen != sizeof(elem))
	return -EINVAL;

      if(copy_from_user(&elem, optval, sizeof(elem)))
	return -EFAULT;

      if((pfr->v_filtering_dev = add_virtual_filtering_device(sock->sk, &elem)) == NULL)
	return -EFAULT;
    }
    break;

  default:
    found = 0;
    break;
  }

  if(found)
    return(ret);
  else
    return(sock_setsockopt(sock, level, optname, optval, optlen));
}

/* ************************************* */

static int ring_getsockopt(struct socket *sock,
			   int level, int optname,
			   char __user * optval, int __user * optlen)
{
  int len;
  struct pf_ring_socket *pfr = ring_sk(sock->sk);

  if(pfr == NULL)
    return(-EINVAL);

  if(get_user(len, optlen))
    return -EFAULT;

  if(len < 0)
    return -EINVAL;

  if(enable_debug)
    printk("[PF_RING] --> getsockopt(%d)\n", optname);

  switch (optname) {
  case SO_GET_RING_VERSION:
    {
      u_int32_t version = RING_VERSION_NUM;

      if(len < sizeof(u_int32_t))
	return -EINVAL;
      else if(copy_to_user(optval, &version, sizeof(version)))
	return -EFAULT;
    }
    break;

  case PACKET_STATISTICS:
    {
      struct tpacket_stats st;

      if(len < sizeof(struct tpacket_stats))
	return -EINVAL;

      st.tp_packets = pfr->slots_info->tot_insert;
      st.tp_drops = pfr->slots_info->tot_lost;

      if(copy_to_user(optval, &st, len))
	return -EFAULT;
      break;
    }

  case SO_GET_HASH_FILTERING_RULE_STATS:
    {
      int rc = -EFAULT;

      if(len >= sizeof(hash_filtering_rule)) {
	hash_filtering_rule rule;
	u_int hash_idx;

	if(pfr->sw_filtering_hash == NULL) {
	  printk("[PF_RING] so_get_hash_filtering_rule_stats(): no hash failure\n");
	  return -EFAULT;
	}

	if(copy_from_user(&rule, optval, sizeof(rule))) {
	  printk("[PF_RING] so_get_hash_filtering_rule_stats: copy_from_user() failure\n");
	  return -EFAULT;
	}

	if(enable_debug)
	  printk("[PF_RING] so_get_hash_filtering_rule_stats"
		 "(vlan=%u, proto=%u, sip=%u, sport=%u, dip=%u, dport=%u)\n",
		 rule.vlan_id, rule.proto,
		 rule.host4_peer_a, rule.port_peer_a,
		 rule.host4_peer_b,
		 rule.port_peer_b);

	hash_idx = hash_pkt(rule.vlan_id, rule.proto,
			    rule.host_peer_a, rule.host_peer_b,
			    rule.port_peer_a, rule.port_peer_b) % DEFAULT_RING_HASH_SIZE;

	if(pfr->sw_filtering_hash[hash_idx] != NULL) {
	  sw_filtering_hash_bucket *bucket;

	  read_lock(&pfr->ring_rules_lock);
	  bucket = pfr->sw_filtering_hash[hash_idx];

	  if(enable_debug)
	    printk("[PF_RING] so_get_hash_filtering_rule_stats(): bucket=%p\n",
		   bucket);

	  while(bucket != NULL) {
	    if(hash_bucket_match_rule(bucket, &rule)) {
	      char *buffer = kmalloc(len, GFP_ATOMIC);

	      if(buffer == NULL) {
		printk("[PF_RING] so_get_hash_filtering_rule_stats() no memory failure\n");
		rc = -EFAULT;
	      } else {
		if((plugin_registration[rule.plugin_action.plugin_id] == NULL)
		   ||
		   (plugin_registration[rule.plugin_action.plugin_id]->pfring_plugin_get_stats == NULL)) {
		  printk("[PF_RING] Found rule but pluginId %d is not registered\n",
			 rule.plugin_action.plugin_id);
		  rc = -EFAULT;
		} else
		  rc = plugin_registration[rule.plugin_action.plugin_id]->
		    pfring_plugin_get_stats(pfr, NULL, bucket, buffer, len);

		if(rc > 0) {
		  if(copy_to_user(optval, buffer, rc)) {
		    printk("[PF_RING] copy_to_user() failure\n");
		    rc = -EFAULT;
		  }
		}
	      }
	      break;
	    } else
	      bucket = bucket->next;
	  }	/* while */

	  read_unlock(&pfr->ring_rules_lock);
	} else {
	  if(enable_debug)
	    printk("[PF_RING] so_get_hash_filtering_rule_stats(): entry not found [hash_idx=%d]\n",
		   hash_idx);
	}
      }

      return(rc);
      break;
    }

  case SO_GET_FILTERING_RULE_STATS:
    {
      char *buffer = NULL;
      int rc = -EFAULT;
      struct list_head *ptr, *tmp_ptr;
      u_int16_t rule_id;

      if(len < sizeof(rule_id))
	return -EINVAL;

      if(copy_from_user(&rule_id, optval, sizeof(rule_id)))
	return -EFAULT;

      if(enable_debug)
	printk("[PF_RING] SO_GET_FILTERING_RULE_STATS: rule_id=%d\n",
	       rule_id);

      read_lock(&pfr->ring_rules_lock);
      list_for_each_safe(ptr, tmp_ptr, &pfr->sw_filtering_rules) {
	sw_filtering_rule_element *rule;

	rule = list_entry(ptr, sw_filtering_rule_element, list);

	if(rule->rule.rule_id == rule_id) {
	  buffer = kmalloc(len, GFP_ATOMIC);

	  if(buffer == NULL)
	    rc = -EFAULT;
	  else {
	    if((plugin_registration[rule->rule.plugin_action.plugin_id] == NULL)
	       ||
	       (plugin_registration[rule->rule.plugin_action.plugin_id]->pfring_plugin_get_stats == NULL)) {
	      printk("[PF_RING] Found rule %d but pluginId %d is not registered\n",
		     rule_id, rule->rule.plugin_action.plugin_id);
	      rc = -EFAULT;
	    } else
	      rc = plugin_registration[rule->rule.plugin_action.plugin_id]->
		pfring_plugin_get_stats(pfr, rule, NULL, buffer, len);

	    if(rc > 0) {
	      if(copy_to_user(optval, buffer, rc)) {
		rc = -EFAULT;
	      }
	    }
	  }
	  break;
	}
      }

      read_unlock(&pfr->ring_rules_lock);
      if(buffer != NULL)
	kfree(buffer);

      /* printk("[PF_RING] SO_GET_FILTERING_RULE_STATS *END*\n"); */
      return(rc);
      break;
    }

  case SO_GET_MAPPED_DNA_DEVICE:
    {
      if((pfr->dna_device == NULL) || (len < sizeof(dna_device)))
	return -EFAULT;

      if(copy_to_user(optval, pfr->dna_device, sizeof(dna_device)))
	return -EFAULT;

      break;
    }

  case SO_GET_NUM_RX_CHANNELS:
    {
      u_int8_t num_rx_channels;

      if(pfr->ring_netdev == &none_device_element) {
	/* Device not yet bound */
	num_rx_channels = UNKNOWN_NUM_RX_CHANNELS;
      } else {
	num_rx_channels = pfr->num_rx_channels;
      }

      if(copy_to_user(optval, &num_rx_channels, sizeof(num_rx_channels)))
	return -EFAULT;
    }
    break;

  case SO_GET_RING_ID:
    if(len < sizeof(pfr->ring_id))
      return -EINVAL;

    if(enable_debug)
      printk("[PF_RING] --> SO_GET_RING_ID=%d\n", pfr->ring_id);

    if(copy_to_user(optval, &pfr->ring_id, sizeof(pfr->ring_id)))
      return -EFAULT;
    break;

  case SO_GET_PACKET_CONSUMER_MODE:
    if(len < sizeof(pfr->kernel_consumer_plugin_id))
      return -EINVAL;

    if(enable_debug)
      printk("[PF_RING] --> SO_GET_PACKET_CONSUMER_MODE=%d\n",
	     pfr->kernel_consumer_plugin_id);

    if(copy_to_user(optval, &pfr->kernel_consumer_plugin_id,
		    sizeof(pfr->kernel_consumer_plugin_id)))
      return -EFAULT;
    break;

  default:
    return -ENOPROTOOPT;
  }

  if(put_user(len, optlen))
    return -EFAULT;
  else
    return(0);
}

/* ************************************* */

void dna_device_handler(dna_device_operation operation,
			unsigned long packet_memory,
			u_int packet_memory_num_slots,
			u_int packet_memory_slot_len,
			u_int packet_memory_tot_len,
			void *descr_packet_memory,
			u_int descr_packet_memory_num_slots,
			u_int descr_packet_memory_slot_len,
			u_int descr_packet_memory_tot_len,
			u_int channel_id,
			void *phys_card_memory,
			u_int phys_card_memory_len,
			struct net_device *netdev,
			dna_device_model device_model,
			u_char *device_address,
			wait_queue_head_t * packet_waitqueue,
			u_int8_t * interrupt_received,
			void *adapter_ptr,
			dna_wait_packet wait_packet_function_ptr,
			dna_device_notify dev_notify_function_ptr)
{
  if(enable_debug)
    printk("[PF_RING] dna_device_handler(%s)\n", netdev->name);

  if(operation == add_device_mapping) {
    dna_device_list *next;

    next = kmalloc(sizeof(dna_device_list), GFP_ATOMIC);
    if(next != NULL) {
      next->dev.packet_memory = packet_memory;
      next->dev.packet_memory_num_slots = packet_memory_num_slots;
      next->dev.packet_memory_slot_len = packet_memory_slot_len;
      next->dev.packet_memory_tot_len = packet_memory_tot_len;
      next->dev.descr_packet_memory = descr_packet_memory;
      next->dev.descr_packet_memory_num_slots = descr_packet_memory_num_slots;
      next->dev.descr_packet_memory_slot_len =  descr_packet_memory_slot_len;
      next->dev.descr_packet_memory_tot_len =   descr_packet_memory_tot_len;
      next->dev.phys_card_memory = phys_card_memory;
      next->dev.phys_card_memory_len = phys_card_memory_len;
      next->dev.channel_id = channel_id;
      next->dev.netdev = netdev;
      next->dev.device_model = device_model;
      next->dev.device_address = device_address;
      next->dev.packet_waitqueue = packet_waitqueue;
      next->dev.interrupt_received = interrupt_received;
      next->dev.adapter_ptr = adapter_ptr;
      next->dev.wait_packet_function_ptr = wait_packet_function_ptr;
      next->dev.usage_notification = dev_notify_function_ptr;
      list_add(&next->list, &ring_dna_devices_list);
      dna_devices_list_size++;
      /* Increment usage count to avoid unloading it while DNA modules are in use */
      try_module_get(THIS_MODULE);
    } else {
      printk("[PF_RING] Could not kmalloc slot!!\n");
    }
  } else {
    struct list_head *ptr, *tmp_ptr;
    dna_device_list *entry;

    list_for_each_safe(ptr, tmp_ptr, &ring_dna_devices_list) {
      entry = list_entry(ptr, dna_device_list, list);

      if((entry->dev.netdev == netdev)
	 && (entry->dev.channel_id == channel_id)) {
	list_del(ptr);
	kfree(entry);
	dna_devices_list_size--;
	/* Decrement usage count for DNA devices */
	module_put(THIS_MODULE);
	break;
      }
    }
  }

  if(enable_debug)
    printk("[PF_RING] dna_device_handler(%s): [dna_devices_list_size=%d]\n",
	   netdev->name, dna_devices_list_size);
}

/* ************************************* */

static int ring_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
  switch (cmd) {
#ifdef CONFIG_INET
  case SIOCGIFFLAGS:
  case SIOCSIFFLAGS:
  case SIOCGIFCONF:
  case SIOCGIFMETRIC:
  case SIOCSIFMETRIC:
  case SIOCGIFMEM:
  case SIOCSIFMEM:
  case SIOCGIFMTU:
  case SIOCSIFMTU:
  case SIOCSIFLINK:
  case SIOCGIFHWADDR:
  case SIOCSIFHWADDR:
  case SIOCSIFMAP:
  case SIOCGIFMAP:
  case SIOCSIFSLAVE:
  case SIOCGIFSLAVE:
  case SIOCGIFINDEX:
  case SIOCGIFNAME:
  case SIOCGIFCOUNT:
  case SIOCSIFHWBROADCAST:
    return(inet_dgram_ops.ioctl(sock, cmd, arg));
#endif

  default:
    return -ENOIOCTLCMD;
  }

  return 0;
}

/* ************************************* */

static struct proto_ops ring_ops = {
  .family = PF_RING,
  .owner = THIS_MODULE,

  /* Operations that make no sense on ring sockets. */
  .connect = sock_no_connect,
  .socketpair = sock_no_socketpair,
  .accept = sock_no_accept,
  .getname = sock_no_getname,
  .listen = sock_no_listen,
  .shutdown = sock_no_shutdown,
  .sendpage = sock_no_sendpage,

  /* Now the operations that really occur. */
  .release = ring_release,
  .bind = ring_bind,
  .mmap = ring_mmap,
  .poll = ring_poll,
  .setsockopt = ring_setsockopt,
  .getsockopt = ring_getsockopt,
  .ioctl = ring_ioctl,
  .recvmsg = ring_recvmsg,
  .sendmsg = ring_sendmsg,
};

/* ************************************ */

static struct net_proto_family ring_family_ops = {
  .family = PF_RING,
  .create = ring_create,
  .owner = THIS_MODULE,
};

// BD: API changed in 2.6.12, ref:
// http://svn.clkao.org/svnweb/linux/revision/?rev=28201
#if(LINUX_VERSION_CODE > KERNEL_VERSION(2,6,11))
static struct proto ring_proto = {
  .name = "PF_RING",
  .owner = THIS_MODULE,
  .obj_size = sizeof(struct ring_sock),
};
#endif

/* ************************************ */

static struct pfring_hooks ring_hooks = {
  .magic = PF_RING,
  .transparent_mode = &transparent_mode,
  .ring_handler = skb_ring_handler,
  .buffer_ring_handler = buffer_ring_handler,
  .buffer_add_hdr_to_ring = add_hdr_to_ring,
  .pfring_registration = register_plugin,
  .pfring_unregistration = unregister_plugin,
  .ring_dna_device_handler = dna_device_handler,
};

/* ************************************ */

void remove_device_from_ring_list(struct net_device *dev) {
  struct list_head *ptr, *tmp_ptr;

  list_for_each_safe(ptr, tmp_ptr, &ring_aware_device_list) {
    ring_device_element *dev_ptr = list_entry(ptr, ring_device_element, device_list);

    if(dev_ptr->dev == dev) {
      struct list_head *ring_ptr, *ring_tmp_ptr;

      if(dev_ptr->proc_entry) {
#ifdef ENABLE_PROC_WRITE_RULE
	if(dev_ptr->device_type != standard_nic_family)
	  remove_proc_entry(PROC_RULES, dev_ptr->proc_entry);
#endif

	remove_proc_entry(PROC_INFO, dev_ptr->proc_entry);
	remove_proc_entry(dev_ptr->dev->name, ring_proc_dev_dir);
      }

      /* We now have to "un-bind" existing sockets */
      list_for_each_safe(ring_ptr, ring_tmp_ptr, &ring_table) {
	struct ring_element   *entry = list_entry(ring_ptr, struct ring_element, list);
	struct pf_ring_socket *pfr = ring_sk(entry->sk);

	pfr->ring_netdev = &none_device_element; /* Unbinding socket */
      }

      list_del(ptr);
      kfree(dev_ptr);
      break;
    }
  }
}

/* ************************************ */

int add_device_to_ring_list(struct net_device *dev) {
  ring_device_element *dev_ptr;

  if((dev_ptr = kmalloc(sizeof(ring_device_element), GFP_KERNEL)) == NULL)
    return(-ENOMEM);

  memset(dev_ptr, 0, sizeof(ring_device_element));
  INIT_LIST_HEAD(&dev_ptr->device_list);
  dev_ptr->dev = dev;
  dev_ptr->proc_entry = proc_mkdir(dev_ptr->dev->name, ring_proc_dev_dir);
  dev_ptr->device_type = standard_nic_family; /* Default */

  create_proc_read_entry(PROC_INFO, 0 /* read-only */,
			 dev_ptr->proc_entry,
			 ring_proc_dev_get_info /* read */,
			 dev_ptr);

#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31))
  /* Dirty trick to fix at some point used to discover Intel 82599 interfaces: FIXME */
  if((dev_ptr->dev->ethtool_ops != NULL) && (dev_ptr->dev->ethtool_ops->set_eeprom != NULL)) {
    struct ethtool_eeprom eeprom; /* Used to to the magic [MAGIC_HW_FILTERING_RULE_REQUEST] */
    int rc;

    eeprom.len = 0 /* check */, eeprom.magic = MAGIC_HW_FILTERING_RULE_REQUEST;

    rc = dev_ptr->dev->ethtool_ops->set_eeprom(dev_ptr->dev, &eeprom, (u8*)NULL);

    if(enable_debug)
      printk("[PF_RING] set_eeprom returned %d\n", rc);

    if(rc == 0) {
      /* This device supports hardware filtering */
      dev_ptr->device_type = intel_82599_family;

      /* Setup handlers */
      dev_ptr->hw_filters.filter_handlers.five_tuple_handler = i82599_generic_handler;
      dev_ptr->hw_filters.filter_handlers.perfect_filter_handler = i82599_generic_handler;

#ifdef ENABLE_PROC_WRITE_RULE
      entry = create_proc_read_entry(PROC_RULES, 0666 /* rw */,
				     dev_ptr->proc_entry,
				     ring_proc_dev_rule_read, dev_ptr);
      if(entry) {
	entry->write_proc = ring_proc_dev_rule_write;
	printk("[PF_RING] Device %s (Intel 82599) DOES support hardware packet filtering\n", dev->name);
      } else
	printk("[PF_RING] Error while creating /proc entry 'rules' for device %s\n", dev->name);
#endif
    } else
      printk("[PF_RING] Device %s does NOT support hardware packet filtering [1]\n", dev->name);
  } else
    printk("[PF_RING] Device %s does NOT support hardware packet filtering [2]\n", dev->name);
#endif

  list_add(&dev_ptr->device_list, &ring_aware_device_list);

  return(0);
}

/* ************************************ */

void pf_ring_add_module_dependency(void) {
  /* Don't actually do anything */
}
EXPORT_SYMBOL(pf_ring_add_module_dependency);

/* ************************************ */

static int ring_notifier(struct notifier_block *this, unsigned long msg, void *data)
{
  struct net_device *dev = data;
  struct pfring_hooks *hook;

  if(dev != NULL) {
    if(enable_debug) printk("[PF_RING] packet_notifier(%lu)\n", msg);

    /* Skip non ethernet interfaces */
    if(strncmp(dev->name, "eth", 3) && strncmp(dev->name, "lan", 3)) {
      if(enable_debug) printk("[PF_RING] packet_notifier(%s): skipping non ethernet device\n", dev->name);
      return NOTIFY_DONE;
    }

    switch(msg) {
    case NETDEV_PRE_UP:
    case NETDEV_UP:
    case NETDEV_DOWN:
      break;
    case NETDEV_REGISTER:
      if(enable_debug)
	printk("[PF_RING] packet_notifier(%s) [REGISTER][pfring_ptr=%p][hook=%p]\n",
	       dev->name, dev->pfring_ptr, &ring_hooks);

      if(dev->pfring_ptr == NULL) {
	dev->pfring_ptr = &ring_hooks;
	if(add_device_to_ring_list(dev) != 0) {
	  printk("[PF_RING] Error in add_device_to_ring_list(%s)\n", dev->name);
	}
      }
      break;

    case NETDEV_UNREGISTER:
      if(enable_debug)
	printk("[PF_RING] packet_notifier(%s) [UNREGISTER][pfring_ptr=%p]\n",
	       dev->name, dev->pfring_ptr);

      hook = (struct pfring_hooks*)dev->pfring_ptr;
      if(hook && (hook->magic == PF_RING)) {
	remove_device_from_ring_list(dev);
	dev->pfring_ptr = NULL;
      }
      /* We don't have to worry updating rules that might have used this
	 device (just removed) as reflection device. This because whenever
	 we set a rule with reflection, we do dev_put() so such device is
	 busy until we remove the rule
      */
      break;

    case NETDEV_CHANGE:     /* Interface state change */
    case NETDEV_CHANGEADDR: /* Interface address changed (e.g. during device probing) */
      break;
    case NETDEV_CHANGENAME: /* Rename interface ethX -> ethY */
      {
	struct list_head *ptr, *tmp_ptr;

	if(enable_debug) printk("[PF_RING] Device change name %s\n", dev->name);

	list_for_each_safe(ptr, tmp_ptr, &ring_aware_device_list) {
	  ring_device_element *dev_ptr = list_entry(ptr, ring_device_element, device_list);

	  if(dev_ptr->dev == dev) {
	    if(enable_debug)
	      printk("[PF_RING] ==>> FOUND device change name %s -> %s\n",
		     dev_ptr->proc_entry->name, dev->name);

	    /* Remove old entry */
#ifdef ENABLE_PROC_WRITE_RULE
	    if(dev_ptr->device_type != standard_nic_family)
	      remove_proc_entry(PROC_RULES, dev_ptr->proc_entry);
#endif

	    remove_proc_entry(PROC_INFO, dev_ptr->proc_entry);
	    remove_proc_entry(dev_ptr->proc_entry->name, ring_proc_dev_dir);
	    /* Add new entry */
	    dev_ptr->proc_entry = proc_mkdir(dev_ptr->dev->name, ring_proc_dev_dir);
	    create_proc_read_entry(PROC_INFO, 0 /* read-only */,
				   dev_ptr->proc_entry,
				   ring_proc_dev_get_info /* read */,
				   dev_ptr);

#ifdef ENABLE_PROC_WRITE_RULE
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31))
	    if(dev_ptr->device_type != standard_nic_family) {
	      struct proc_dir_entry *entry;

	      entry= create_proc_read_entry(PROC_RULES, 0666 /* rw */,
					    dev_ptr->proc_entry,
					    ring_proc_dev_rule_read,
					    dev_ptr);
	      if(entry)
		entry->write_proc = ring_proc_dev_rule_write;
	    }
#endif
#endif

	    dev_ptr->proc_entry->name = dev->name;
	    break;
	  }
	}
      }
      break;

    default:
      if(enable_debug)
	printk("[PF_RING] packet_notifier(%s): unhandled message [msg=%lu][pfring_ptr=%p]\n",
	       dev->name, msg, dev->pfring_ptr);
      break;
    }
  }

  return NOTIFY_DONE;
}

/* ************************************ */

static struct notifier_block ring_netdev_notifier = {
  .notifier_call = ring_notifier,
};

/* ************************************ */

static void __exit ring_exit(void)
{
  struct list_head *ptr, *tmp_ptr;
  struct ring_element *entry;
  struct pfring_hooks *hook;

  pfring_enabled = 0;

  unregister_device_handler();

  list_for_each_safe(ptr, tmp_ptr, &ring_table) {
    entry = list_entry(ptr, struct ring_element, list);
    list_del(ptr);
    kfree(entry);
  }

  list_for_each_safe(ptr, tmp_ptr, &ring_aware_device_list) {
    ring_device_element *dev_ptr;

    dev_ptr = list_entry(ptr, ring_device_element, device_list);
    hook = (struct pfring_hooks*)dev_ptr->dev->pfring_ptr;

#ifdef ENABLE_PROC_WRITE_RULE
    /* Remove /proc entry for the selected device */
    if(dev_ptr->device_type != standard_nic_family)
      remove_proc_entry(PROC_RULES, dev_ptr->proc_entry);
#endif

    remove_proc_entry(PROC_INFO, dev_ptr->proc_entry);
    remove_proc_entry(dev_ptr->dev->name, ring_proc_dev_dir);

    if(hook->magic == PF_RING) {
      printk("[PF_RING] Unregister hook for %s\n", dev_ptr->dev->name);
      dev_ptr->dev->pfring_ptr = NULL; /* Unhook PF_RING */
    }

    list_del(ptr);
    kfree(dev_ptr);
  }

  list_for_each_safe(ptr, tmp_ptr, &ring_cluster_list) {
    ring_cluster_element *cluster_ptr;

    cluster_ptr = list_entry(ptr, ring_cluster_element, list);

    list_del(ptr);
    kfree(cluster_ptr);
  }

  list_for_each_safe(ptr, tmp_ptr, &ring_dna_devices_list) {
    dna_device_list *elem;

    elem = list_entry(ptr, dna_device_list, list);

    list_del(ptr);
    kfree(elem);
  }

  sock_unregister(PF_RING);
#if(LINUX_VERSION_CODE > KERNEL_VERSION(2,6,11))
  proto_unregister(&ring_proto);
#endif
  unregister_netdevice_notifier(&ring_netdev_notifier);
  ring_proc_term();

  printk("[PF_RING] unloaded\n");
}

/* ************************************ */

static int __init ring_init(void)
{
  static struct net_device any_dev, none_dev;
  int i;
#if(LINUX_VERSION_CODE > KERNEL_VERSION(2,6,11))
  int rc;
#endif

  printk("[PF_RING] Welcome to PF_RING %s ($Revision: %s$)\n"
	 "(C) 2004-11 L.Deri <deri@ntop.org>\n",
	 RING_VERSION, SVN_REV);

#if(LINUX_VERSION_CODE > KERNEL_VERSION(2,6,11))
  if((rc = proto_register(&ring_proto, 0)) != 0)
    return(rc);
#endif

  INIT_LIST_HEAD(&ring_table);
  INIT_LIST_HEAD(&virtual_filtering_devices_list);
  INIT_LIST_HEAD(&ring_cluster_list);
  INIT_LIST_HEAD(&ring_aware_device_list);
  INIT_LIST_HEAD(&ring_dna_devices_list);

  for(i = 0; i < MAX_NUM_DEVICES; i++)
    INIT_LIST_HEAD(&device_ring_list[i]);

  init_ring_readers();

  memset(&any_dev, 0, sizeof(any_dev));
  strcpy(any_dev.name, "any");
  any_dev.ifindex = MAX_NUM_IFIDX-1, any_dev.type = ARPHRD_ETHER;
  memset(&any_device_element, 0, sizeof(any_device_element));
  any_device_element.dev = &any_dev, any_device_element.device_type = standard_nic_family;

  memset(&none_dev, 0, sizeof(none_dev));
  strcpy(none_dev.name, "none");
  none_dev.ifindex = MAX_NUM_IFIDX-2;
  memset(&none_device_element, 0, sizeof(none_device_element));
  none_device_element.dev = &none_dev, none_device_element.device_type = standard_nic_family;

  ring_proc_init();
  sock_register(&ring_family_ops);
  register_netdevice_notifier(&ring_netdev_notifier);

  /* Sanity check */
  if(transparent_mode > driver2pf_ring_non_transparent)
    transparent_mode = standard_linux_path;

  printk("[PF_RING] Min # ring slots %d\n", min_num_slots);
  printk("[PF_RING] Slot version     %d\n",
	 RING_FLOWSLOT_VERSION);
  printk("[PF_RING] Capture TX       %s\n",
	 enable_tx_capture ? "Yes [RX+TX]" : "No [RX only]");
  printk("[PF_RING] Transparent Mode %d\n",
	 transparent_mode);
  printk("[PF_RING] IP Defragment    %s\n",
	 enable_ip_defrag ? "Yes" : "No");
  printk("[PF_RING] Initialized correctly\n");

  register_device_handler();

  pfring_enabled = 1;
  return 0;
}

module_init(ring_init);
module_exit(ring_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Luca Deri <deri@ntop.org>");
MODULE_DESCRIPTION("Packet capture acceleration and analysis");

MODULE_ALIAS_NETPROTO(PF_RING);
