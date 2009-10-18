/* This RX patch applies only to non-NAPI drivers */

#if defined (CONFIG_RING) || defined(CONFIG_RING_MODULE)
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0))
if(ring_handler && ring_handler(skb, 1, 1, -1 /* Unknown channel */)) {
  /* The packet has been copied into a ring */
  return(NET_RX_SUCCESS);
}
#endif
#endif /* CONFIG_RING */
