#if defined (CONFIG_RING) || defined(CONFIG_RING_MODULE)
	if(ring_handler) ring_handler(skb, 0, 1);
#endif /* CONFIG_RING */

