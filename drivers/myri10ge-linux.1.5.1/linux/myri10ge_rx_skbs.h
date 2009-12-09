/*************************************************************************
 * myri10ge_rx_skb.h: Myricom Myri-10G Ethernet driver receive code
 *
 * Copyright (C) 2005 - 2009 Myricom, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of Myricom, Inc. nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 *
 * If the eeprom on your board is not recent enough, you will need to get a
 * newer firmware image at:
 *   http://www.myri.com/scs/download-Myri10GE.html
 *
 * Contact Information:
 *   <help@myri.com>
 *   Myricom, Inc., 325N Santa Anita Avenue, Arcadia, CA 91006
 *************************************************************************/

/* 
 * This file holds optional code to receive directly into skbs,
 * rather than attached pages.
 */

/*
 * Set of routines to get a new receive buffer.  Any buffer which
 * crosses a 4KB boundary must start on a 4KB boundary due to PCIe
 * wdma restrictions. We also try to align any smaller allocation to
 * at least a 16 byte boundary for efficiency.  We assume the linux
 * memory allocator works by powers of 2, and will not return memory
 * smaller than 2KB which crosses a 4KB boundary.  If it does, we fall
 * back to allocating 2x as much space as required.
 *
 * We intend to replace large (>4KB) skb allocations by using
 * pages directly and building a fraglist in the near future.
 */

#define MYRI10GE_RX_ALIGN 128UL

static inline struct sk_buff *
myri10ge_alloc_big(struct net_device *dev, int bytes)
{
	struct sk_buff *skb;
	unsigned long data, roundup;

#ifdef MYRI10GE_RELAX_RX_ALIGN
	skb = myri10ge_netdev_alloc_skb(dev, bytes + MXGEFW_PAD + MYRI10GE_RX_ALIGN);
	if (skb == NULL)
		return NULL;
	
	data = (unsigned long)(skb->data);
	roundup = (-data) & (MYRI10GE_RX_ALIGN - 1UL);
	skb_reserve(skb, roundup);

	return skb;
#else
	skb = myri10ge_netdev_alloc_skb(dev, bytes + 4096 + MXGEFW_PAD);
	if (skb == NULL)
		return NULL;

	/* Correct skb->truesize so that socket buffer
	 * accounting is not confused the rounding we must
	 * do to satisfy alignment constraints.
	 */
	myri10ge_reduce_truesize(skb, 4096);

	data = (unsigned long)(skb->data);
	roundup = (-data) & (4095);
	skb_reserve(skb, roundup);
	return skb;
#endif
}

/* Allocate 2x as much space as required and use whichever portion
   does not cross a 4KB boundary */
static inline struct sk_buff *
myri10ge_alloc_small_safe(struct net_device *dev, unsigned int bytes)
{
	struct sk_buff *skb;
	unsigned long data, boundary;

	skb = myri10ge_netdev_alloc_skb(dev, 2 * (bytes + MXGEFW_PAD) - 1);
	if (unlikely(skb == NULL))
		return NULL;

	/* Correct skb->truesize so that socket buffer
	 * accounting is not confused the rounding we must
	 * do to satisfy alignment constraints.
	 */
	myri10ge_reduce_truesize(skb, bytes + MXGEFW_PAD);

	data = (unsigned long)(skb->data);
	boundary = (data + 4095UL) & ~4095UL;
	if ((boundary - data) >= (bytes + MXGEFW_PAD))
		return skb;

	skb_reserve(skb, boundary - data);
	return skb;
}

static int myri10ge_skb_cross_4k = 0;

/* Allocate just enough space, and verify that the allocated
   space does not cross a 4KB boundary */
static inline struct sk_buff *
myri10ge_alloc_small(struct net_device *dev, int bytes)
{
	struct sk_buff *skb;
	unsigned long roundup, data, end;

	skb = myri10ge_netdev_alloc_skb(dev, bytes + MYRI10GE_RX_ALIGN + MXGEFW_PAD);
	if (unlikely(skb == NULL))
		return NULL;

	/* Round allocated buffer to 16 byte boundary */
	data = (unsigned long)(skb->data);
	roundup = (-data) & (MYRI10GE_RX_ALIGN - 1UL);
	skb_reserve(skb, roundup);
	/* Verify that the data buffer does not cross a page boundary */
	data = (unsigned long)(skb->data);
	end = data + bytes + MXGEFW_PAD - 1;
#ifndef MYRI10GE_RELAX_RX_ALIGN
	if (unlikely (((end >> 12) != (data >> 12)) && (data & 4095UL))) {
		printk(KERN_NOTICE "myri10ge_alloc_small: small skb crossed 4KB boundary\n");
		myri10ge_skb_cross_4k = 1;
		dev_kfree_skb_any(skb);
		skb = myri10ge_alloc_small_safe(dev, bytes);
	}
#endif
	return skb;
}

static inline int
myri10ge_getbuf(struct myri10ge_rx_buf *rx, struct myri10ge_priv *mgp, int bytes, int idx)
{
	struct net_device *dev = mgp->dev;
	struct pci_dev *pdev = mgp->pdev;
	struct sk_buff *skb;
	dma_addr_t bus;
	int len, retval = 0;

	bytes += VLAN_HLEN;	/* account for 802.1q vlan tag */

	if ((bytes + MXGEFW_PAD) >
	    (4096 - 16) /* linux overhead */)
		skb = myri10ge_alloc_big(dev, bytes);
	else if (myri10ge_skb_cross_4k)
		skb = myri10ge_alloc_small_safe(dev, bytes);
	else
		skb = myri10ge_alloc_small(dev, bytes);

	if (unlikely(skb == NULL)) {
		rx->alloc_fail++;
		retval = -ENOBUFS;
		goto done;
	}

	/* set len so that it only covers the area we
	   need mapped for DMA */
	len = bytes + MXGEFW_PAD;

	bus = myri10ge_pci_map_skb_data(pdev, skb, len, PCI_DMA_FROMDEVICE);
	rx->info[idx].rx__skb = skb;
	pci_unmap_addr_set(&rx->info[idx], bus, bus);
	pci_unmap_len_set(&rx->info[idx], len, len);
	rx->shadow[idx].addr_low = htonl(MYRI10GE_LOWPART_TO_U32(bus));
	rx->shadow[idx].addr_high = htonl(MYRI10GE_HIGHPART_TO_U32(bus));

done:
	/* copy 8 descriptors (64-bytes) to the mcp at a time */
	if ((idx & 7) == 7) {
		myri10ge_submit_8rx(&rx->lanai[idx - 7],
				    &rx->shadow[idx - 7]);
	}
	return retval;
}

#ifdef MYRI10GE_HAVE_VLAN_OFFLOAD
static int myri10ge_get_skb_header(struct sk_buff *skb,
				   void **ip_hdr,  void **tcpudp_hdr,
				   u64 *hdr_flags, void *priv);
static int
myri10ge_vlan_rx(struct myri10ge_slice_state *ss, struct sk_buff *skb, __wsum csum)
{
	struct myri10ge_priv *mgp = ss->mgp;
	struct ethhdr *eh = (struct ethhdr *)skb->data;
	struct vlan_ethhdr *veth;
	char *va;
	void *iph, *tcpudp_hdr;
	u64 hdr_flags;
	u16 vlan_TCI, proto;

	vlan_TCI = 0;
	if (mgp->vlan_group != NULL && eh->h_proto == ntohs(ETH_P_8021Q)) {
		/* fix csum */
		va = (char *)skb->data;
		csum = csum_sub(csum, csum_partial(va + ETH_HLEN,
						   VLAN_HLEN, 0));
		/* pop tag */
		veth = (struct vlan_ethhdr *)va;
		vlan_TCI = ntohs(veth->h_vlan_TCI);
		proto = veth->h_vlan_encapsulated_proto;
		myri10ge_memmove(va + VLAN_HLEN, va, ETH_HLEN);
		skb_pull(skb, VLAN_HLEN);
		eh = (struct ethhdr *)skb->data;
		eh->h_proto = proto;
	}
	skb->protocol = eth_type_trans(skb, mgp->dev);
	if (mgp->csum_flag) {
		if ((skb->protocol == ntohs(ETH_P_IP)) ||
		    (skb->protocol == ntohs(ETH_P_IPV6))) {
			skb->csum = csum;
			skb->ip_summed = CHECKSUM_COMPLETE;
			/* if a packet is marked CHECKSUM_UNNECESSARY,
			 *  then ESX4 will do LRO on it above the driver
			 */
			if (!myri10ge_get_skb_header(skb,
						     &iph, &tcpudp_hdr,
						     &hdr_flags,
						     (void *)(unsigned long)csum)) {
				skb->ip_summed = CHECKSUM_UNNECESSARY;
			}
		}
	}
	/* ESX4 needs NAPI pointer */
	skb->napi = &ss->napi;
	if (vlan_TCI) {
		vlan_hwaccel_receive_skb(skb, mgp->vlan_group, vlan_TCI);
	} else {
		netif_receive_skb(skb);
	}
	myri10ge_set_last_rx(mgp->dev, jiffies);
	return 1;
}
#endif 

static inline unsigned long
myri10ge_rx_done_skb(struct myri10ge_slice_state *ss,
		     struct myri10ge_rx_buf *rx, int bytes, int len, int csum)
{
	struct myri10ge_priv *mgp = ss->mgp;
	dma_addr_t bus;
	struct sk_buff *skb;
	int idx, fill_idx, unmap_len;

	idx = rx->cnt & rx->mask;
	rx->cnt++;

	/* save a pointer to the received skb */
	skb = rx->info[idx].rx__skb;
	bus = pci_unmap_addr(&rx->info[idx], bus);
	unmap_len = pci_unmap_len(&rx->info[idx], len);

	/* try to replace the received skb */
	fill_idx = (rx->fill_offset + idx) & rx->mask;
	if (myri10ge_getbuf(rx, mgp, bytes, fill_idx)) {
		/* drop the frame -- the old skbuf is re-cycled */
		rx->info[idx].rx__skb = NULL;		
		rx->info[fill_idx].rx__skb = skb;
		pci_unmap_addr_set(&rx->info[fill_idx], bus, bus);
		pci_unmap_len_set(&rx->info[fill_idx], len, len);
		ss->stats.rx_dropped += 1;
		return 0;
	}

	/* unmap the recvd skb */
	pci_unmap_single(mgp->pdev,
			 bus, unmap_len,
			 PCI_DMA_FROMDEVICE);

	/* mcp implicitly skips 1st bytes so that packet is properly
	 * aligned */
	skb_reserve(skb, MXGEFW_PAD);

	/* set the length of the frame */
	skb_put(skb, len);

	myri10ge_report_queue(skb, ss - mgp->ss);

#ifdef MYRI10GE_HAVE_VLAN_OFFLOAD
	return myri10ge_vlan_rx(ss, skb, csum);
#endif

	skb->protocol = eth_type_trans(skb, mgp->dev);
#ifdef HAVE_PF_RING
	{
	  int debug = 0;
	  struct pfring_hooks *hook = (struct pfring_hooks*)skb->dev->pfring_ptr;
	  
	  if(hook && (hook->magic == PF_RING)) {
	    /* Wow: PF_RING is alive & kickin' ! */
	    int rc;

	    if(debug) 
	      printk(KERN_INFO "[PF_RING] alive [%s][len=%d]\n", 
		     skb->dev->name, skb->len);

	    // printk(KERN_INFO "[PF_RING] queue_index=%d\n", ring->queue_index);

	    if(*hook->transparent_mode != standard_linux_path) {
	      rc = hook->ring_handler(skb, 1, 1, ss - &mgp->ss[0]);
	      
	      if(rc == 1 /* Packet handled by PF_RING */) {
		if(*hook->transparent_mode == driver2pf_ring_non_transparent) {
		  /* PF_RING has already freed the memory */
		  return 0;
		}
	      }
	    } else {
	      if(debug) printk(KERN_INFO "[PF_RING] not present on %s\n", 
			       skb->dev->name);
	    }
	  }
	}

#endif

	if (mgp->csum_flag) {
		if ((skb->protocol == ntohs(ETH_P_IP)) ||
		    (skb->protocol == ntohs(ETH_P_IPV6))) {
			skb->csum = csum;
			skb->ip_summed = CHECKSUM_COMPLETE;
		} else
			myri10ge_vlan_ip_csum(skb, csum);
#if MYRI10GE_LRO
		if (mgp->dev->features & NETIF_F_LRO) {
			lro_receive_skb(&ss->rx_done.lro_mgr, skb,
					(void *)(unsigned long)csum);
			myri10ge_set_last_rx(mgp->dev, jiffies);
			return 1;
		}
#endif
	}

#ifdef MYRI10GE_NAPI
#ifdef MYRI10GE_HAVE_GRO_SKB
	if (mgp->dev->features & NETIF_F_GRO)
		napi_gro_receive(&ss->napi, skb);
	else
#endif /* MYRI10GE_HAVE_GRO_SKB */
	netif_receive_skb(skb);
#else
	netif_rx(skb);
#endif
	myri10ge_set_last_rx(mgp->dev, jiffies);
	return 1;
}
