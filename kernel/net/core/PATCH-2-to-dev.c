#if defined (CONFIG_RING) || defined(CONFIG_RING_MODULE)
/*
  This patch doesn't seem to be used anymore as it can result
  in capturing the same packet twice
  Marketakis Yannis <marketak@ics.forth.gr>
*/
#if 0
	if(ring_handler && ring_handler(skb, 1, 1)) {
	  /* The packet has been copied into a ring */
	  return(NET_RX_SUCCESS);
	}
#endif
#endif /* CONFIG_RING */

