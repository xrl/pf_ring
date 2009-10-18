#if defined (CONFIG_RING) || defined(CONFIG_RING_MODULE)
#include <linux/version.h>

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0))
#include <linux/ring.h>

EXPORT_SYMBOL(get_skb_ring_handler);
EXPORT_SYMBOL(set_skb_ring_handler);
EXPORT_SYMBOL(do_skb_ring_handler);
EXPORT_SYMBOL(get_buffer_ring_handler);
EXPORT_SYMBOL(set_buffer_ring_handler);
EXPORT_SYMBOL(do_buffer_ring_handler);
#endif

#endif
