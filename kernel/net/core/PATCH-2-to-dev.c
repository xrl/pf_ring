#if defined (CONFIG_RING) || defined(CONFIG_RING_MODULE)
	if(ring_handler && ring_handler(skb, 1, 1)) {
	  /* The packet has been copied into a ring */
	  return(NET_RX_SUCCESS);
	}
#endif /* CONFIG_RING */

