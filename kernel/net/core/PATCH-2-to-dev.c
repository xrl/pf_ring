#if defined (CONFIG_RING) || defined(CONFIG_RING_MODULE)
/*
  Incoming packets might be duplicated on non-NAPI drivers

  Marketakis Yannis <marketak@ics.forth.gr>
*/
	if(ring_handler && ring_handler(skb, 1, 1)) {
	  /* The packet has been copied into a ring */
	  return(NET_RX_SUCCESS);
	}
#endif /* CONFIG_RING */

