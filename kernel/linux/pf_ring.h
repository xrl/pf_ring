/*
 *
 * Definitions for packet ring
 *
 * 2004-10 Luca Deri <deri@ntop.org>
 *
 */

#ifndef __RING_H
#define __RING_H

#ifdef __KERNEL__
#include <linux/in6.h>
#else
#include <netinet/in.h>
#endif /* __KERNEL__ */

#define INCLUDE_MAC_INFO

#ifdef INCLUDE_MAC_INFO
#define SKB_DISPLACEMENT    14 /* Include MAC address information */
#else
#define SKB_DISPLACEMENT    0  /* Do NOT include MAC address information */
#endif

#define RING_MAGIC
#define RING_MAGIC_VALUE             0x88
#define RING_FLOWSLOT_VERSION          11

#define DEFAULT_BUCKET_LEN            128
#define MAX_NUM_DEVICES               256

/* Dirty hack I know, but what else shall I do man? */
#define pfring_ptr ec_ptr

/* Versioning */
#define RING_VERSION                "4.3.1"
#define RING_VERSION_NUM           0x040301

/* Set */
#define SO_ADD_TO_CLUSTER                 99
#define SO_REMOVE_FROM_CLUSTER           100
#define SO_SET_STRING                    101
#define SO_ADD_FILTERING_RULE            102
#define SO_REMOVE_FILTERING_RULE         103
#define SO_TOGGLE_FILTER_POLICY          104
#define SO_SET_SAMPLING_RATE             105
#define SO_ACTIVATE_RING                 106
#define SO_RING_BUCKET_LEN               107
#define SO_SET_CHANNEL_ID                108
#define SO_PURGE_IDLE_HASH_RULES         109 /* inactivity (sec) */
#define SO_SET_APPL_NAME                 110
#define SO_SET_PACKET_DIRECTION          111
#define SO_SET_REFLECTION_DEVICE         112
#define SO_SET_MASTER_RING               113
#define SO_ADD_HW_FILTERING_RULE         114
#define SO_DEL_HW_FILTERING_RULE         115

/* Get */
#define SO_GET_RING_VERSION              120
#define SO_GET_FILTERING_RULE_STATS      121
#define SO_GET_HASH_FILTERING_RULE_STATS 122
#define SO_GET_MAPPED_DNA_DEVICE         123
#define SO_GET_NUM_RX_CHANNELS           124
#define SO_GET_RING_ID                   125

/* Map */
#define SO_MAP_DNA_DEVICE                130


#define REFLECTOR_NAME_LEN                 8

#ifndef IN6ADDR_ANY_INIT
#define IN6ADDR_ANY_INIT { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 } } }
#endif

#ifndef NETDEV_PRE_UP
#define NETDEV_PRE_UP  0x000D
#endif

/* *********************************** */

struct pkt_aggregation_info {
  u_int32_t num_pkts, num_bytes;
  struct timeval first_seen, last_seen;
};

/*
  Note that as offsets *can* be negative,
  please do not change them to unsigned
*/
struct pkt_offset {
  int16_t eth_offset; /* This offset *must* be added to all offsets below */
  int16_t vlan_offset;
  int16_t l3_offset;
  int16_t l4_offset;
  int16_t payload_offset;
};


#ifndef ETH_ALEN
#define ETH_ALEN  6
#endif

#define REFLECT_PACKET_DEVICE_NONE     0

typedef union {
  struct in6_addr v6;  /* IPv6 src/dst IP addresses (Network byte order) */
  u_int32_t v4;        /* IPv4 src/dst IP addresses */
} ip_addr;

#define ipv4_tos ip_tos
#define ipv6_tos ip_tos
#define ipv4_src ip_src.v4
#define ipv4_dst     ip_dst.v4
#define ipv6_src     ip_src.v6
#define ipv6_dst     ip_dst.v6
#define host4_low    host_low.v4
#define host4_high   host_high.v4
#define host6_low    host_low.v6
#define host6_high   host_high.v6
#define host4_peer_a host_peer_a.v4
#define host4_peer_b host_peer_b.v4
#define host6_peer_a host_peer_a.v6
#define host6_peer_b host_peer_b.v6

struct pkt_parsing_info {
  /* Core fields (also used by NetFlow) */
  u_int8_t dmac[ETH_ALEN], smac[ETH_ALEN];  /* MAC src/dst addresses */
  u_int16_t eth_type;   /* Ethernet type */
  u_int16_t vlan_id;    /* VLAN Id or NO_VLAN */
  u_int8_t  ip_version;
  u_int8_t  l3_proto, ip_tos;   /* Layer 3 protocol/TOS */
  ip_addr   ip_src, ip_dst;   /* IPv4 src/dst IP addresses */
  u_int16_t l4_src_port, l4_dst_port; /* Layer 4 src/dst ports */
  struct {
    u_int8_t flags;   /* TCP flags (0 if not available) */
    u_int32_t seq_num; /* TCP sequence number */
  } tcp;
  u_int16_t last_matched_plugin_id; /* If > 0 identifies a plugin to that matched the packet */
  u_int16_t last_matched_rule_id; /* If > 0 identifies a rule that matched the packet */

  union {
    struct pkt_offset offset; /* Offsets of L3/L4/payload elements */
    struct pkt_aggregation_info aggregation; /* Future or plugin use */
  } pkt_detail;
};

struct pfring_pkthdr {
  struct timeval ts;    /* time stamp */
  u_int32_t caplen;     /* length of portion present */
  u_int32_t len;        /* length this packet (off wire) */
  int if_index;         /* index of the interface on which the packet has been received */
  struct pkt_parsing_info parsed_pkt; /* packet parsing info */
  u_int16_t parsed_header_len; /* Extra parsing data before packet */
};

/* *********************************** */

#define NO_PLUGIN_ID        0
#define MAX_PLUGIN_ID      64
#define MAX_PLUGIN_FIELDS  32

/* ************************************************* */

typedef struct {
  u_int8_t dmac[ETH_ALEN], smac[ETH_ALEN]; /* Use '0' (zero-ed MAC address) for any MAC address.
				  This is applied to both source and destination. */
  u_int16_t vlan_id;                 /* Use '0' for any vlan */
  u_int8_t  proto;                   /* Use 0 for 'any' protocol */
  ip_addr   host_low, host_high;     /* User '0' for any host. This is applied to both source
					and destination. */
  u_int16_t port_low, port_high;     /* All ports between port_low...port_high
					0 means 'any' port. This is applied to both source
					and destination. This means that
					(proto, sip, sport, dip, dport) matches the rule if
					one in "sip & sport", "sip & dport" "dip & sport"
					match. */
} filtering_rule_core_fields;

/* ************************************************* */

#define FILTER_PLUGIN_DATA_LEN   256

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
  execute_action_and_continue_rule_evaluation,
  forward_packet_add_rule_and_stop_rule_evaluation,
  reflect_packet_and_stop_rule_evaluation,
  reflect_packet_and_continue_rule_evaluation
} rule_action_behaviour;

typedef enum {
  rx_and_tx_direction = 0,
  rx_only_direction,
  tx_only_direction
} packet_direction;

typedef enum {
  standard_linux_path = 0, /* Business as usual */
  driver2pf_ring_transparent = 1, /* Packets are still delivered to the kernel */
  driver2pf_ring_non_transparent = 2 /* Packets not delivered to the kernel */
} direct2pf_ring;

typedef struct {
  unsigned long jiffies_last_match;  /* Jiffies of the last rule match (updated by pf_ring) */
  void *reflector_dev; /* Reflector device (struct net_device*) */
} filtering_internals;

typedef struct {
  u_int16_t rule_id;                 /* Rules are processed in order from lowest to higest id */
  rule_action_behaviour rule_action; /* What to do in case of match */
  u_int8_t balance_id, balance_pool; /* If balance_pool > 0, then pass the packet above only if the
					(hash(proto, sip, sport, dip, dport) % balance_pool)
					= balance_id */
  filtering_rule_core_fields     core_fields;
  filtering_rule_extended_fields extended_fields;
  filtering_rule_plugin_action   plugin_action;
  char reflector_device_name[REFLECTOR_NAME_LEN];

  filtering_internals internals;   /* PF_RING internal fields */
} filtering_rule;

/* *********************************** */

typedef struct {
  u_int8_t  proto;
  u_int32_t s_addr, d_addr;
  u_int16_t s_port, d_port;
} five_tuple_filter_hw_rule;

typedef struct {
  u_int16_t vlan_id;
  u_int8_t  proto;
  u_int32_t s_addr, d_addr;
  u_int16_t s_port, d_port;
} perfect_filter_hw_rule;

typedef enum {
  five_tuple_rule,
  perfect_filter_rule
} hw_filtering_rule_type;

typedef struct {
  hw_filtering_rule_type rule_type;
  u_int16_t rule_id, queue_id;
  union {
    five_tuple_filter_hw_rule five_tuple_rule;
    perfect_filter_hw_rule perfect_rule;
  } rule;
} hw_filtering_rule;

#define MAGIC_HW_FILTERING_RULE_ELEMENT  0x29010020

#define RULE_COMMAND        1
#define CHECK_COMMAND       2

typedef struct {
  u_int8_t add_rule, command;
  hw_filtering_rule rule;
} hw_filtering_rule_element;

/* *********************************** */

/* Hash size used for precise packet matching */
#define DEFAULT_RING_HASH_SIZE     4096

/*
 * The hashtable contains only perfect matches: no
 * wildacards or so are accepted.
 */
typedef struct {
  u_int16_t rule_id; /* Future use */
  u_int16_t vlan_id;
  u_int8_t  proto;
  ip_addr host_peer_a, host_peer_b;
  u_int16_t port_peer_a, port_peer_b;

  rule_action_behaviour rule_action; /* What to do in case of match */
  filtering_rule_plugin_action plugin_action;
  char reflector_device_name[REFLECTOR_NAME_LEN];

  filtering_internals internals;   /* PF_RING internal fields */
} hash_filtering_rule;

/* ************************************************* */

typedef struct _filtering_hash_bucket {
  hash_filtering_rule           rule;
  void                          *plugin_data_ptr; /* ptr to a *continuous* memory area
						     allocated by the plugin */
  u_int16_t                     plugin_data_ptr_len;
  struct _filtering_hash_bucket *next;
} filtering_hash_bucket;

/* *********************************** */

#define RING_MIN_SLOT_SIZE    (60+sizeof(struct pfring_pkthdr))
#define RING_MAX_SLOT_SIZE    (1514+sizeof(struct pfring_pkthdr))

#if !defined(__cplusplus)

#ifndef min
#define min(a,b) ((a < b) ? a : b)
#endif

#ifndef max
#define max(a,b) ((a > b) ? a : b)
#endif

#endif

/* *********************************** */
/* False sharing reference: http://en.wikipedia.org/wiki/False_sharing */

typedef struct flowSlotInfo {
  u_int16_t version, sample_rate;
  u_int32_t tot_slots, slot_len, data_len, tot_mem;
  u_int64_t tot_pkts, tot_lost, tot_insert, tot_read;
  u_int64_t tot_fwd_ok, tot_fwd_notok;
  u_int32_t insert_idx, remove_idx, forward_idx;
} FlowSlotInfo;

/* *********************************** */

typedef struct flowSlot {
#ifdef RING_MAGIC
  u_int8_t     magic;      /* It must alwasy be zero */
#endif
  u_int8_t     slot_state; /* 0=empty, 1=full, 2=reflect on the specified socket reflection device   */
  u_int8_t     bucket;     /* bucket[bucketLen] */
} FlowSlot;

/* *********************************** */

#ifdef __KERNEL__

FlowSlotInfo *getRingPtr(void);
int allocateRing(char *deviceName, u_int numSlots,
		 u_int bucketLen, u_int sampleRate);
unsigned int pollRing(struct file *fp, struct poll_table_struct * wait);
void deallocateRing(void);

/* ************************* */

#endif /* __KERNEL__ */

/* *********************************** */

#define PF_RING          27      /* Packet Ring */
#define SOCK_RING        PF_RING

/* ioctl() */
#define SIORINGPOLL      0x8888

/* ************************************************* */

#ifdef __KERNEL__
struct ring_sock {
  struct sock             sk; /* It MUST be the first element */
  struct packet_type      prot_hook;
  spinlock_t		bind_lock;
};
#endif

/* *********************************** */

typedef int (*dna_wait_packet)(void *adapter, int mode);

typedef enum {
  add_device_mapping = 0, remove_device_mapping
} dna_device_operation;

typedef enum {
  intel_e1000 = 0, intel_igb, intel_ixgbe
} dna_device_model;

typedef struct {
  unsigned long packet_memory;  /* Invalid in userland */
  u_int packet_memory_num_slots;
  u_int packet_memory_slot_len;
  u_int packet_memory_tot_len;
  void *descr_packet_memory;  /* Invalid in userland */
  u_int descr_packet_memory_num_slots;
  u_int descr_packet_memory_slot_len;
  u_int descr_packet_memory_tot_len;
  u_int channel_id;
  char *phys_card_memory; /* Invalid in userland */
  u_int phys_card_memory_len;
  struct net_device *netdev; /* Invalid in userland */
  dna_device_model device_model;
#ifdef __KERNEL__
  wait_queue_head_t *packet_waitqueue;
#else
  void *packet_waitqueue;
#endif
  u_int8_t *interrupt_received, in_use;
  void *adapter_ptr;
  dna_wait_packet wait_packet_function_ptr;
} dna_device;

typedef struct {
  dna_device_operation operation;
  char device_name[8];
  int32_t channel_id;
} dna_device_mapping;

/* ************************************************* */

#define RING_ANY_CHANNEL          ((u_int8_t)-1)
#define UNKNOWN_RX_CHANNEL        RING_ANY_CHANNEL
#define MAX_NUM_RX_CHANNELS       256
#define UNKNOWN_NUM_RX_CHANNELS   1

/* ************************************************* */

typedef enum {
  cluster_per_flow = 0,
  cluster_round_robin
} cluster_type;

struct add_to_cluster {
  u_int clusterId;
  cluster_type the_type;
};

#ifdef __KERNEL__

#define CLUSTER_LEN       8

/*
 * A ring cluster is used group together rings used by various applications
 * so that they look, from the PF_RING point of view, as a single ring.
 * This means that developers can use clusters for sharing packets across
 * applications using various policies as specified in the hashing_mode
 * parameter.
 */
struct ring_cluster {
  u_short        cluster_id; /* 0 = no cluster */
  u_short        num_cluster_elements;
  cluster_type   hashing_mode;
  u_short        hashing_id;
  struct sock    *sk[CLUSTER_LEN];
};

/*
 * Linked-list of ring clusters.
 */
typedef struct {
  struct ring_cluster cluster;
  struct list_head list;
} ring_cluster_element;

typedef struct {
  dna_device dev;
  struct list_head list;
} dna_device_list;

typedef struct {
  struct net_device *dev;
  struct proc_dir_entry *proc_entry;
  u_int8_t has_hw_filtering;
  u_int16_t num_hw_filters;
  struct list_head list;
} ring_device_element;

/* ************************************************* */

/*
 * Linked-list of ring sockets.
 */
struct ring_element {
  struct list_head  list;
  struct sock      *sk;
};

/* ************************************************* */

extern struct ring_opt *pfr; /* Forward */

typedef int (*do_handle_filtering_hash_bucket)(struct ring_opt *pfr,
					       filtering_hash_bucket* rule,
					       u_char add_rule);

/* ************************************************* */

/*
 * Ring options
 */
struct ring_opt {
  u_int8_t ring_active, num_rx_channels;
  struct net_device *ring_netdev;
  u_short ring_pid;
  u_int32_t ring_id;
  char *appl_name; /* String that identifies the application bound to the socket */
  packet_direction direction; /* Specify the capture direction for packets */

  /* Master Ring */
  struct ring_opt *master_ring;

  /* Direct NIC Access */
  u_int8_t mmap_count;
  dna_device *dna_device;

  /* Cluster */
  u_short cluster_id; /* 0 = no cluster */

  /* Channel */
  int32_t channel_id;  /* -1 = any channel */

  /* Reflector Device */
  struct net_device *reflector_dev; /* Reflector device */

  /* Packet buffers */
  unsigned long order;

  /* Ring Slots */
  void * ring_memory;
  u_int32_t bucket_len;
  FlowSlotInfo *slots_info; /* Points to ring_memory */
  char *ring_slots;         /* Points to ring_memory+sizeof(FlowSlotInfo) */

  /* Packet Sampling */
  u_int32_t pktToSample, sample_rate;

  /* BPF Filter */
  struct sk_filter *bpfFilter;

  /* Filtering Rules */
  filtering_hash_bucket **filtering_hash;
  u_int16_t num_filtering_rules;
  u_int8_t rules_default_accept_policy; /* 1=default policy is accept, drop otherwise */
  struct list_head rules;

  /* Locks */
  atomic_t num_ring_users;
  wait_queue_head_t ring_slots_waitqueue;
  rwlock_t ring_index_lock, ring_rules_lock;

  /* Indexes (Internal) */
  u_int insert_page_id, insert_slot_id;

  /* Function pointer */
  do_handle_filtering_hash_bucket handle_hash_rule;
};

/* **************************************** */

/*
 * Linked-list of device rings
 */
typedef struct {
  struct ring_opt *the_ring;
  struct list_head list;
} device_ring_list_element;

/* **************************************** */

#define MAX_NUM_PATTERN   32

typedef struct {
  filtering_rule rule;

#ifdef CONFIG_TEXTSEARCH
  struct ts_config *pattern[MAX_NUM_PATTERN];
#endif
  struct list_head list;

  /* Plugin action */
  void *plugin_data_ptr; /* ptr to a *continuous* memory area allocated by the plugin */
} filtering_rule_element;

struct parse_buffer {
  void      *mem;
  u_int16_t  mem_len;
};

/* **************************************** */

/* Plugins */
/* Execute an action (e.g. update rule stats) */
typedef int (*plugin_handle_skb)(struct ring_opt *the_ring,
				 filtering_rule_element *rule,       /* In case the match is on the list */
				 filtering_hash_bucket *hash_bucket, /* In case the match is on the hash */
				 struct pfring_pkthdr *hdr,
				 struct sk_buff *skb,
				 u_int16_t filter_plugin_id,
				 struct parse_buffer **filter_rule_memory_storage,
				 rule_action_behaviour *behaviour);
/* Return 1/0 in case of match/no match for the given skb */
typedef int (*plugin_filter_skb)(struct ring_opt *the_ring,
				 filtering_rule_element *rule,
				 struct pfring_pkthdr *hdr,
				 struct sk_buff *skb,
				 struct parse_buffer **filter_rule_memory_storage);
/* Get stats about the rule */
typedef int (*plugin_get_stats)(struct ring_opt *pfr,
				filtering_rule_element *rule,
				filtering_hash_bucket  *hash_bucket,
				u_char* stats_buffer, u_int stats_buffer_len);

/* Build a new rule when forward_packet_add_rule_and_stop_rule_evaluation is specified
   return 0 in case of success , an error code (< 0) otherwise */
typedef int (*plugin_add_rule)(filtering_rule_element *rule,
			       struct pfring_pkthdr *hdr,
			       filtering_hash_bucket *hash_bucket);

/* Called when a ring is disposed */
typedef void (*plugin_free_ring_mem)(filtering_rule_element *rule);

struct pfring_plugin_registration {
  u_int16_t plugin_id;
  char name[16];          /* Unique plugin name (e.g. sip, udp) */
  char description[64];   /* Short plugin description */
  plugin_filter_skb    pfring_plugin_filter_skb; /* Filter skb: 1=match, 0=no match */
  plugin_handle_skb    pfring_plugin_handle_skb;
  plugin_get_stats     pfring_plugin_get_stats;
  plugin_free_ring_mem pfring_plugin_free_ring_mem;
  plugin_add_rule      pfring_plugin_add_rule;
};

typedef int   (*register_pfring_plugin)(struct pfring_plugin_registration
					*reg);
typedef int   (*unregister_pfring_plugin)(u_int16_t pfring_plugin_id);
typedef u_int (*read_device_pfring_free_slots)(int ifindex);
typedef void  (*handle_ring_dna_device)(dna_device_operation operation,
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
					wait_queue_head_t *packet_waitqueue,
					u_int8_t *interrupt_received,
					void *adapter_ptr,
					dna_wait_packet wait_packet_function_ptr);

extern register_pfring_plugin get_register_pfring_plugin(void);
extern unregister_pfring_plugin get_unregister_pfring_plugin(void);
extern read_device_pfring_free_slots get_read_device_pfring_free_slots(void);

extern void set_register_pfring_plugin(register_pfring_plugin the_handler);
extern void set_unregister_pfring_plugin(unregister_pfring_plugin the_handler);
extern void set_read_device_pfring_free_slots(read_device_pfring_free_slots the_handler);

extern int do_register_pfring_plugin(struct pfring_plugin_registration *reg);
extern int do_unregister_pfring_plugin(u_int16_t pfring_plugin_id);
extern int do_read_device_pfring_free_slots(int deviceidx);

extern handle_ring_dna_device get_ring_dna_device_handler(void);
extern void set_ring_dna_device_handler(handle_ring_dna_device
					the_dna_device_handler);
extern void do_ring_dna_device_handler(dna_device_operation operation,
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
				       wait_queue_head_t *packet_waitqueue,
				       u_int8_t *interrupt_received,
				       void *adapter_ptr,
				       dna_wait_packet wait_packet_function_ptr);

typedef int (*handle_ring_skb)(struct sk_buff *skb, u_char recv_packet,
			       u_char real_skb, u_int8_t channel_id,
			       u_int8_t num_rx_channels);
typedef int (*handle_ring_buffer)(struct net_device *dev,
				  char *data, int len);
typedef int (*handle_add_hdr_to_ring)(struct ring_opt *pfr,
				      struct pfring_pkthdr *hdr);

/* Hack to jump from a device directly to PF_RING */
struct pfring_hooks {
  u_int32_t magic; /*
		      It should be set to PF_RING
		      and be the first one on this struct
		   */
  unsigned int *transparent_mode;
  handle_ring_skb ring_handler;
  handle_ring_buffer buffer_ring_handler;
  handle_add_hdr_to_ring buffer_add_hdr_to_ring;
  register_pfring_plugin pfring_registration;
  unregister_pfring_plugin pfring_unregistration;
  handle_ring_dna_device ring_dna_device_handler;
  read_device_pfring_free_slots pfring_free_device_slots;
};


#ifdef PF_RING_PLUGIN

static struct pfring_plugin_registration plugin_reg;
static struct list_head plugin_registered_devices_list;
static u_int16_t pfring_plugin_id = 0;

int add_plugin_to_device_list(struct net_device *dev) {
  ring_device_element *dev_ptr;

  printk("[PF_RING] add_plugin_to_device_list(%s, plugin_id=%d)\n",
	 dev->name, pfring_plugin_id);

  if ((dev_ptr = kmalloc(sizeof(ring_device_element),
			 GFP_KERNEL)) == NULL)
    return (-ENOMEM);

  INIT_LIST_HEAD(&dev_ptr->list);
  dev_ptr->dev = dev;

  list_add(&dev_ptr->list, &plugin_registered_devices_list);

  return(0);
}

void remove_plugin_from_device_list(struct net_device *dev) {
  struct list_head *ptr, *tmp_ptr;
  struct pfring_hooks* hook = (struct pfring_hooks*)dev->pfring_ptr;

  if(hook && (hook->magic == PF_RING)) {
    hook->pfring_unregistration(pfring_plugin_id);
  }

  list_for_each_safe(ptr, tmp_ptr, &plugin_registered_devices_list) {
    ring_device_element *dev_ptr;

    dev_ptr = list_entry(ptr, ring_device_element, list);
    if(dev_ptr->dev == dev) {
      list_del(ptr);
      kfree(dev_ptr);
      break;
    }
  }
}

static int ring_plugin_notifier(struct notifier_block *this, unsigned long msg, void *data)
{
  struct net_device *dev = data;
  struct pfring_hooks *hook;

  switch(msg) {
  case NETDEV_REGISTER:
    hook = (struct pfring_hooks*)dev->pfring_ptr;
    if(hook && (hook->magic == PF_RING)) {
      hook->pfring_registration(&plugin_reg);
      add_plugin_to_device_list(dev);
    }
    break;

  case NETDEV_UNREGISTER:
    hook = (struct pfring_hooks*)dev->pfring_ptr;
    if(hook && (hook->magic == PF_RING)) {
      hook->pfring_unregistration(pfring_plugin_id);
    }
    break;
  }

  return NOTIFY_DONE;
}

static struct notifier_block ring_netdev_notifier = {
  .notifier_call = ring_plugin_notifier,
};

static void register_plugin(struct pfring_plugin_registration *reg_info) {
  INIT_LIST_HEAD(&plugin_registered_devices_list);
  memcpy(&plugin_reg, reg_info, sizeof(struct pfring_plugin_registration));
  pfring_plugin_id = reg_info->plugin_id;
  register_netdevice_notifier(&ring_netdev_notifier);
}

static void unregister_plugin(int pfring_plugin_id) {
  struct list_head *ptr, *tmp_ptr;

  unregister_netdevice_notifier(&ring_netdev_notifier);

  list_for_each_safe(ptr, tmp_ptr, &plugin_registered_devices_list) {
    ring_device_element *dev_ptr;
    struct pfring_hooks *hook;

    dev_ptr = list_entry(ptr, ring_device_element, list);
    hook = (struct pfring_hooks*)dev_ptr->dev->pfring_ptr;
    if(hook && (hook->magic == PF_RING)) {
      printk("[PF_RING] Unregister plugin_id %d for %s\n",
	     pfring_plugin_id, dev_ptr->dev->name);
      hook->pfring_unregistration(pfring_plugin_id);
      list_del(ptr);
      kfree(dev_ptr);
    }
  }
}

#endif /* PF_RING_PLUGIN */

#endif /* __KERNEL__  */


/* *********************************** */

#endif /* __RING_H */
