/*
  This RX patch applies to both non-NAPI (this as netif_receive_rx
  is called by netif_rx) and NAPI drivers.
*/
#if defined (CONFIG_RING) || defined(CONFIG_RING_MODULE)
if(ring_handler && ring_handler(skb, 1, 1, -1 /* Unknown channel */)) {
  /* The packet has been copied into a ring */
  return(NET_RX_SUCCESS);
}
#endif /* CONFIG_RING */
