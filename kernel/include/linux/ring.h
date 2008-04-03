/*
 * Definitions for packet ring
 *
 * 2004-08 Luca Deri <deri@ntop.org>
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
#define RING_FLOWSLOT_VERSION           9

/* Versioning */
#define RING_VERSION                "3.7.8"
#define RING_VERSION_NUM           0x030708

/* Set */
#define SO_ADD_TO_CLUSTER                99
#define SO_REMOVE_FROM_CLUSTER           100
#define SO_SET_REFLECTOR                 101
#define SO_SET_STRING                    102
#define SO_ADD_FILTERING_RULE            103
#define SO_REMOVE_FILTERING_RULE         104
#define SO_TOGGLE_FILTER_POLICY          105
#define SO_SET_SAMPLING_RATE             106
#define SO_ACTIVATE_RING                 107

/* Get */
#define SO_GET_RING_VERSION              110
#define SO_GET_FILTERING_RULE_STATS      111
#define SO_GET_HASH_FILTERING_RULE_STATS 112

/* *********************************** */

#define NO_VLAN ((u_int16_t)-1)

struct pkt_parsing_info {
  /* core fields (also used by NetFlow) */
  u_int16_t eth_type;   /* Ethernet type */
  u_int16_t vlan_id;    /* VLAN Id or NO_VLAN */
  u_int8_t  l3_proto, ipv4_tos;   /* Layer 3 protocol/TOS */
  u_int32_t ipv4_src, ipv4_dst;   /* IPv4 src/dst IP addresses */
  u_int16_t l4_src_port, l4_dst_port; /* Layer 4 src/dst ports */
  u_int8_t tcp_flags;   /* TCP flags (0 if not available) */
  /* Offsets of L3/L4/payload elements */
  u_int16_t eth_offset, vlan_offset, l3_offset, l4_offset, payload_offset; 
};

struct pfring_pkthdr {
  struct timeval ts;    /* time stamp */
  u_int32_t caplen;     /* length of portion present */
  u_int32_t len;        /* length this packet (off wire) */
  struct pkt_parsing_info parsed_pkt; /* packet parsing info */
  u_int16_t parsed_header_len; /* Extra parsing data before packet */
}; 

/* *********************************** */

#define MAX_PLUGIN_ID      64
#define MAX_PLUGIN_FIELDS  32

/* ************************************************* */

typedef struct {
  u_int8_t  proto;                   /* Use 0 for 'any' protocol */
  u_int16_t vlan_id;                 /* Use '0' for any vlan */
  u_int32_t host_low, host_high;     /* User '0' for any host. This is applied to both source
				        and destination. */
  u_int16_t port_low, port_high;     /* All ports between port_low...port_high
					0 means 'any' port. This is applied to both source
				        and destination. This means that
					(proto, sip, sport, dip, dport) matches the rule if
					one in "sip & sport", "sip & dport" "dip & sport"
					match. */  
} filtering_rule_core_fields;

/* ************************************************* */

#define FILTER_PLUGIN_DATA_LEN   128

typedef struct {
  char payload_pattern[32];         /* If strlen(payload_pattern) > 0, the packet payload
				       must match the specified pattern */
  u_int16_t filter_plugin_id;       /* If > 0 identifies a plugin to which the datastructure
				       below will be passed for matching */
  char      filter_plugin_data[FILTER_PLUGIN_DATA_LEN]; 
                                    /* Opaque datastructure that is interpreted by the
				       specified plugin and that specifies a filtering
				       criteria to be checked for match. Usually this data
				       is re-casted to a more meaningful datastructure
				    */
} filtering_rule_extended_fields;

/* ************************************************* */

typedef struct {
  /* Plugin Action */
  u_int16_t plugin_id; /* ('0'=no plugin) id of the plugin associated with this rule */
} filtering_rule_plugin_action;

typedef enum {
  forward_packet_and_stop_rule_evaluation = 0,
  dont_forward_packet_and_stop_rule_evaluation,
  execute_action_and_continue_rule_evaluation
} rule_action_behaviour;

typedef struct {
  u_int16_t rule_id;                 /* Rules are processed in order from lowest to higest id */
  rule_action_behaviour rule_action; /* What to do in case of match */
  u_int8_t balance_id, balance_pool; /* If balance_pool > 0, then pass the packet above only if the
					(hash(proto, sip, sport, dip, dport) % balance_pool) 
					= balance_id */
  filtering_rule_core_fields     core_fields;
  filtering_rule_extended_fields extended_fields;
  filtering_rule_plugin_action   plugin_action;
} filtering_rule;

/* *********************************** */

#define DEFAULT_RING_HASH_SIZE     4096

/*
 * The hashtable contains only perfect matches: no
 * wildacards or so are accepted.
*/
typedef struct {
  u_int16_t vlan_id;
  u_int8_t  proto;
  u_int32_t host_peer_a, host_peer_b;
  u_int16_t port_peer_a, port_peer_b;

  rule_action_behaviour rule_action; /* What to do in case of match */
  filtering_rule_plugin_action plugin_action;  
} hash_filtering_rule;

/* ************************************************* */

typedef struct _filtering_hash_bucket {
  hash_filtering_rule           rule;
  void                          *plugin_data_ptr; /* ptr to a *continuous* memory area
						     allocated by the plugin */  
  u_int16_t                     plugin_data_ptr_len;
  struct _filtering_hash_bucket *next;
} filtering_hash_bucket;

/* ************************************************* */

#ifdef __KERNEL__

typedef struct {
  filtering_rule rule;
#ifdef CONFIG_TEXTSEARCH
  struct ts_config *pattern;
#endif
  struct list_head list;
  
  /* Plugin action */
  void *plugin_data_ptr; /* ptr to a *continuous* memory area allocated by the plugin */  
} filtering_rule_element;

struct parse_buffer {
  void      *mem;
  u_int16_t  mem_len;
};

/* Plugins */
/* Execute an action (e.g. update rule stats) */
typedef int (*plugin_handle_skb)(filtering_rule_element *rule,       /* In case the match is on the list */
				 filtering_hash_bucket *hash_bucket, /* In case the match is on the hash */
				 struct pfring_pkthdr *hdr,
				 struct sk_buff *skb,
				 u_int16_t filter_plugin_id,
				 struct parse_buffer *filter_rule_memory_storage);
/* Return 1/0 in case of match/no match for the given skb */
typedef int (*plugin_filter_skb)(filtering_rule_element *rule, 
				 struct pfring_pkthdr *hdr,
				 struct sk_buff *skb,
				 struct parse_buffer **filter_rule_memory_storage);
/* Get stats about the rule */
typedef int (*plugin_get_stats)(filtering_rule_element *rule,
				filtering_hash_bucket  *hash_bucket,
				u_char* stats_buffer, u_int stats_buffer_len);

struct pfring_plugin_registration {
  u_int16_t plugin_id;
  char name[16];          /* Unique plugin name (e.g. sip, udp) */
  char description[64];   /* Short plugin description */
  plugin_filter_skb pfring_plugin_filter_skb; /* Filter skb: 1=match, 0=no match */
  plugin_handle_skb pfring_plugin_handle_skb;
  plugin_get_stats  pfring_plugin_get_stats;
};

typedef int (*register_pfring_plugin)(struct pfring_plugin_registration *reg);
typedef int (*unregister_pfring_plugin)(u_int16_t pfring_plugin_id);

extern register_pfring_plugin get_register_pfring_plugin(void);
extern unregister_pfring_plugin get_unregister_pfring_plugin(void);
extern void set_register_pfring_plugin(register_pfring_plugin the_handler);
extern void set_unregister_pfring_plugin(unregister_pfring_plugin the_handler);

extern int do_register_pfring_plugin(struct pfring_plugin_registration *reg);
extern int do_unregister_pfring_plugin(u_int16_t pfring_plugin_id);

#endif

/* *********************************** */

enum cluster_type {
  cluster_per_flow = 0,
  cluster_round_robin
};

/* *********************************** */

#define RING_MIN_SLOT_SIZE    (60+sizeof(struct pfring_pkthdr))
#define RING_MAX_SLOT_SIZE    (1514+sizeof(struct pfring_pkthdr))

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

#ifdef __KERNEL__

FlowSlotInfo* getRingPtr(void);
int allocateRing(char *deviceName, u_int numSlots,
		 u_int bucketLen, u_int sampleRate);
unsigned int pollRing(struct file *fp, struct poll_table_struct * wait);
void deallocateRing(void);

/* ************************* */

typedef int (*handle_ring_skb)(struct sk_buff *skb, u_char recv_packet, u_char real_skb);
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
