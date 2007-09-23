/*
 * Definitions for packet ring
 *
 * 2004-07 Luca Deri <deri@ntop.org>
 */
#ifndef __RING_H
#define __RING_H

#define INCLUDE_MAC_INFO

#ifdef INCLUDE_MAC_INFO
#define SKB_DISPLACEMENT    14 /* Include MAC address information */
#else
#define SKB_DISPLACEMENT    0  /* Do NOT include MAC address information */
#endif

#define RING_MAGIC
#define RING_MAGIC_VALUE             0x88
#define RING_FLOWSLOT_VERSION           8

/* Versioning */
#define RING_VERSION              "3.6.3"
#define RING_VERSION_NUM         0x030603

/* Set */
#define SO_ADD_TO_CLUSTER         99
#define SO_REMOVE_FROM_CLUSTER   100
#define SO_SET_REFLECTOR         101
#define SO_SET_STRING            102
#define SO_ADD_FILTERING_RULE    103
#define SO_REMOVE_FILTERING_RULE 104
#define SO_TOGGLE_FILTER_POLICY  105
#define SO_SET_SAMPLING_RATE     106

/* Get */
#define SO_GET_RING_VERSION      110

/* *********************************** */

#ifndef HAVE_PCAP

struct pcap_pkthdr {
  struct timeval ts;    /* time stamp */
  u_int32_t caplen;     /* length of portion present */
  u_int32_t len;        /* length this packet (off wire) */
  /* packet parsing info */
  u_int16_t eth_type;   /* Ethernet type */
  u_int16_t vlan_id;    /* VLAN Id or -1 for no vlan */
  u_int8_t  l3_proto, ipv4_tos;   /* Layer 3 protocol/TOS */
  u_int16_t l3_offset, l4_offset, payload_offset; /* Offsets of L3/L4/payload elements */
  u_int32_t ipv4_src, ipv4_dst;   /* IPv4 src/dst IP addresses */
  u_int16_t l4_src_port, l4_dst_port; /* Layer 4 src/dst ports */
  u_int8_t tcp_flags;   /* TCP flags (0 if not available) */
};
#endif

/* *********************************** */

enum cluster_type {
  cluster_per_flow = 0,
  cluster_round_robin
};

/* *********************************** */

#define RING_MIN_SLOT_SIZE    (60+sizeof(struct pcap_pkthdr))
#define RING_MAX_SLOT_SIZE    (1514+sizeof(struct pcap_pkthdr))

#ifndef min
#define min(a,b) ((a < b) ? a : b)
#endif

/* *********************************** */

typedef struct flowSlotInfo {
  u_int16_t version, sample_rate;
  u_int32_t tot_slots, slot_len, data_len, tot_mem;
  
  u_int64_t tot_pkts, tot_lost;
  u_int64_t tot_insert, tot_read;  
  u_int32_t insert_idx, remove_idx;
} FlowSlotInfo;

/* *********************************** */

typedef struct flowSlot {
#ifdef RING_MAGIC
  u_char     magic;      /* It must alwasy be zero */
#endif
  u_char     slot_state; /* 0=empty, 1=full   */
  u_char     bucket;     /* bucket[bucketLen] */
} FlowSlot;

/* *********************************** */

typedef struct {
  u_int16_t rule_id;                 /* Rules are processed in order from lowest to higest id */
  u_int8_t pass_action;              /* 0=drop packet if match rule, pass packet otherwise */
  u_int8_t balance_id, balance_pool; /* If balance_pool > 0, then pass the packet
					above only if the 
					(hash(proto, sip, sport, dip, dport) % balance_pool) = balance_id
				     */
  u_int8_t proto;                    /* Use 0 for 'any' protocol */
  u_int16_t vlan_id;                 /* Use '0' for any vlan */
  u_int32_t host_ip, host_netmask;   /* Netmask 0 means 'any' host. This is applied to both source
				        and destination.
				     */
  u_int16_t port_low, port_high;     /* All ports between port_low...port_high 
					0 means 'any' port. This is applied to both source
				        and destination. This means that 
					(proto, sip, sport, dip, dport) matches the rule if
					one in "sip & sport", "sip & dport" "dip & sport"
					match.
				     */
  char payload_pattern[32];          /* If strlen(payload_pattern) > 0, the packet payload
					must match the specified pattern
				     */
} filtering_rule;

/* *********************************** */

#ifdef __KERNEL__ 

FlowSlotInfo* getRingPtr(void);
int allocateRing(char *deviceName, u_int numSlots,
		 u_int bucketLen, u_int sampleRate);
unsigned int pollRing(struct file *fp, struct poll_table_struct * wait);
void deallocateRing(void);

/* ************************* */

typedef int (*handle_ring_skb)(struct sk_buff *skb,
			       u_char recv_packet, u_char real_skb);
extern handle_ring_skb get_skb_ring_handler(void);
extern void set_skb_ring_handler(handle_ring_skb the_handler);
extern void do_skb_ring_handler(struct sk_buff *skb,
				u_char recv_packet, u_char real_skb);

typedef int (*handle_ring_buffer)(struct net_device *dev, 
				  char *data, int len);
extern handle_ring_buffer get_buffer_ring_handler(void);
extern void set_buffer_ring_handler(handle_ring_buffer the_handler);
extern int do_buffer_ring_handler(struct net_device *dev,
				  char *data, int len);
#endif /* __KERNEL__  */

/* *********************************** */

#define PF_RING          27      /* Packet Ring */
#define SOCK_RING        PF_RING

/* ioctl() */
#define SIORINGPOLL      0x8888

/* *********************************** */

#endif /* __RING_H */
