#if defined (CONFIG_RING) || defined(CONFIG_RING_MODULE)

/* #define RING_DEBUG */

#include <linux/ring.h>
#include <linux/version.h>

/* ************************************************ */

static handle_ring_skb ring_handler = NULL;

handle_ring_skb get_skb_ring_handler() { return(ring_handler); }

void set_skb_ring_handler(handle_ring_skb the_handler) {
  ring_handler = the_handler;
}

void do_skb_ring_handler(struct sk_buff *skb,
			 u_char recv_packet, u_char real_skb) {
  if(ring_handler)
    ring_handler(skb, recv_packet, real_skb, -1 /* Unknown channel */);
}

/* ************************************************ */

static handle_ring_buffer buffer_ring_handler = NULL;

handle_ring_buffer get_buffer_ring_handler() { return(buffer_ring_handler); }

void set_buffer_ring_handler(handle_ring_buffer the_handler) {
  buffer_ring_handler = the_handler;
}

int do_buffer_ring_handler(struct net_device *dev, char *data, int len) {
  if(buffer_ring_handler) {
    buffer_ring_handler(dev, data, len);
    return(1);
  } else 
    return(0);
}

/* ******************* */

static handle_add_hdr_to_ring buffer_add_hdr_to_ring = NULL;

handle_add_hdr_to_ring get_add_hdr_to_ring() { return(buffer_add_hdr_to_ring); }

void set_add_hdr_to_ring(handle_add_hdr_to_ring the_handler) {
  buffer_add_hdr_to_ring = the_handler;
}

int do_add_hdr_to_ring(struct ring_opt *pfr, struct pfring_pkthdr *hdr) {
  if(buffer_add_hdr_to_ring) {
    buffer_add_hdr_to_ring(pfr, hdr);
    return(1);
  } else 
    return(0);
}

/* ************************************************ */

static register_pfring_plugin pfring_registration = NULL;

register_pfring_plugin get_register_pfring_plugin() { return(pfring_registration); }

void set_register_pfring_plugin(register_pfring_plugin the_handler) {
  pfring_registration = the_handler;
}

int do_register_pfring_plugin(struct pfring_plugin_registration *reg) {
  if(pfring_registration) {
    pfring_registration(reg);
    return(1);
  } else
    return(0);
}

/* ************************************************ */

static unregister_pfring_plugin pfring_unregistration = NULL;

unregister_pfring_plugin get_unregister_pfring_plugin() { return(pfring_unregistration); }

void set_unregister_pfring_plugin(unregister_pfring_plugin the_handler) {
  pfring_unregistration = the_handler;
}

int do_unregister_pfring_plugin(u_int16_t pfring_plugin_id) {
  if(pfring_unregistration) {
    pfring_unregistration(pfring_plugin_id);
    return(1);
  } else
    return(0);
}

/* ************************************************ */

static handle_ring_dna_device ring_dna_device_handler = NULL;

handle_ring_dna_device get_ring_dna_device_handler() { return(ring_dna_device_handler); }

void set_ring_dna_device_handler(handle_ring_dna_device the_dna_device_handler) {
  ring_dna_device_handler = the_dna_device_handler;
}

void do_ring_dna_device_handler(dna_device_operation operation,
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
				u_int8_t *interrupt_received) {
  if(ring_dna_device_handler)
    ring_dna_device_handler(operation,
			    packet_memory,
			    packet_memory_num_slots,
			    packet_memory_slot_len,
			    packet_memory_tot_len,
			    descr_packet_memory,
			    descr_packet_memory_num_slots,
			    descr_packet_memory_slot_len,
			    descr_packet_memory_tot_len, channel_id,
			    phys_card_memory, phys_card_memory_len,
			    netdev, device_model, packet_waitqueue,
			    interrupt_received);
}

/* ************************************************ */

static read_device_pfring_free_slots pfring_free_device_slots = NULL;

read_device_pfring_free_slots get_read_device_pfring_free_slots() { return(pfring_free_device_slots); }

void set_read_device_pfring_free_slots(read_device_pfring_free_slots the_handler) {
  pfring_free_device_slots = the_handler;
}

int do_read_device_pfring_free_slots(int deviceidx) {
  if(pfring_free_device_slots) {    
    return(pfring_free_device_slots(deviceidx));
  } else
    return(0);
}

/* ************************************************ */

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0))
EXPORT_SYMBOL(get_skb_ring_handler);
EXPORT_SYMBOL(set_skb_ring_handler);
EXPORT_SYMBOL(do_skb_ring_handler);

EXPORT_SYMBOL(get_buffer_ring_handler);
EXPORT_SYMBOL(set_buffer_ring_handler);
EXPORT_SYMBOL(do_buffer_ring_handler);

EXPORT_SYMBOL(get_add_hdr_to_ring);
EXPORT_SYMBOL(set_add_hdr_to_ring);
EXPORT_SYMBOL(do_add_hdr_to_ring);

EXPORT_SYMBOL(get_register_pfring_plugin);
EXPORT_SYMBOL(set_register_pfring_plugin);
EXPORT_SYMBOL(do_register_pfring_plugin);

EXPORT_SYMBOL(get_unregister_pfring_plugin);
EXPORT_SYMBOL(set_unregister_pfring_plugin);
EXPORT_SYMBOL(do_unregister_pfring_plugin);

EXPORT_SYMBOL(get_ring_dna_device_handler);
EXPORT_SYMBOL(set_ring_dna_device_handler);
EXPORT_SYMBOL(do_ring_dna_device_handler);

EXPORT_SYMBOL(get_read_device_pfring_free_slots);
EXPORT_SYMBOL(set_read_device_pfring_free_slots);
EXPORT_SYMBOL(do_read_device_pfring_free_slots);

#endif

#endif
