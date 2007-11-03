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
    ring_handler(skb, recv_packet, real_skb);
}

/* ******************* */

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

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0))
EXPORT_SYMBOL(get_skb_ring_handler);
EXPORT_SYMBOL(set_skb_ring_handler);
EXPORT_SYMBOL(do_skb_ring_handler);

EXPORT_SYMBOL(get_buffer_ring_handler);
EXPORT_SYMBOL(set_buffer_ring_handler);
EXPORT_SYMBOL(do_buffer_ring_handler);

EXPORT_SYMBOL(get_register_pfring_plugin);
EXPORT_SYMBOL(set_register_pfring_plugin);
EXPORT_SYMBOL(do_register_pfring_plugin);

EXPORT_SYMBOL(get_unregister_pfring_plugin);
EXPORT_SYMBOL(set_unregister_pfring_plugin);
EXPORT_SYMBOL(do_unregister_pfring_plugin);
#endif

#endif
