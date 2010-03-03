#ifdef BCM_HAS_SKB_DMA_MAP

#define tg3_skb_dma_addr(tnapi, sp, entry, i)   ((sp)->dma_maps[(i)])
#define tg3_skb_dma_map(tnapi, skb, dir)        skb_dma_map(&(tnapi)->tp->pdev->dev, (skb), (dir))
#define tg3_skb_dma_unmap(tnapi, skb, dir)      skb_dma_unmap(&(tnapi)->tp->pdev->dev, (skb), (dir))

#else /* BCM_HAS_SKB_DMA_MAP */

#ifndef BCM_HAS_DMA_DATA_DIRECTION
enum dma_data_direction {
	DMA_BIDIRECTIONAL = 0,
	DMA_TO_DEVICE = 1,
	DMA_FROM_DEVICE = 2,
	DMA_NONE = 3,
};
#endif

#ifdef BCM_HAS_NEW_PCI_DMA_MAPPING_ERROR
#define tg3_pci_dma_mapping_error(pdev, mapping)  pci_dma_mapping_error((pdev), (mapping))
#elif defined(BCM_HAS_PCI_DMA_MAPPING_ERROR)
#define tg3_pci_dma_mapping_error(pdev, mapping)  pci_dma_mapping_error((mapping))
#else
#define tg3_pci_dma_mapping_error(pdev, mapping)  0
#endif

#define tg3_skb_dma_addr(tnapi, sp, entry, i)  (tnapi)->tx_buffers[(entry)].mapping;

static int tg3_skb_dma_map(struct tg3_napi *tnapi, struct sk_buff *skb,
			   enum dma_data_direction dir)
{
	struct skb_shared_info *sp = skb_shinfo(skb);
	struct tg3 *tp = tnapi->tp;
	dma_addr_t mapping;
	int i;
	u32 entry, errent;

	/* Queue skb data, a.k.a. the main skb fragment. */
	mapping = pci_map_single(tp->pdev, skb->data,
				 skb_headlen(skb), PCI_DMA_TODEVICE);

	if (tg3_pci_dma_mapping_error(tp->pdev, mapping))
		goto out_err;

	entry = tnapi->tx_prod;

	tnapi->tx_buffers[entry].mapping = mapping;
	entry = NEXT_TX(entry);

	for (i = 0; i < sp->nr_frags; i++) {
		skb_frag_t *fp = &sp->frags[i];

		mapping = pci_map_page(tp->pdev, fp->page, fp->page_offset,
				       fp->size, PCI_DMA_TODEVICE);

		if (tg3_pci_dma_mapping_error(tp->pdev, mapping))
			goto unwind;

		tnapi->tx_buffers[entry].mapping = mapping;
		entry = NEXT_TX(entry);
	}

	return 0;

unwind:
	errent = tnapi->tx_prod;

	pci_unmap_single(tp->pdev,
			 tnapi->tx_buffers[errent].mapping,
			 skb_headlen(skb), PCI_DMA_TODEVICE);
	errent = NEXT_TX(errent);

	while (errent != entry) {
		skb_frag_t *fp = &sp->frags[i];

		pci_unmap_page(tp->pdev,
			       tnapi->tx_buffers[errent].mapping,
			       fp->size, PCI_DMA_TODEVICE);
		errent = NEXT_TX(errent);
	}

out_err:
	return -ENOMEM;
}

static void tg3_skb_dma_unmap(struct tg3_napi *tnapi, struct sk_buff *skb,
			      enum dma_data_direction dir)
{
	struct skb_shared_info *sp = skb_shinfo(skb);
	struct tg3 *tp = tnapi->tp;
	int i;
	u32 entry = tnapi->tx_cons;

	pci_unmap_single(tp->pdev,
			 tnapi->tx_buffers[entry].mapping,
			 skb_headlen(skb), PCI_DMA_TODEVICE);
	entry = NEXT_TX(entry);

	for (i = 0; i < sp->nr_frags; i++) {
		skb_frag_t *fp = &sp->frags[i];

		pci_unmap_page(tp->pdev,
			       tnapi->tx_buffers[entry].mapping,
			       fp->size, PCI_DMA_TODEVICE);
		entry = NEXT_TX(entry);
	}
}

#endif /* BCM_HAS_SKB_DMA_MAP */


#ifdef HAVE_POLL_CONTROLLER
#define CONFIG_NET_POLL_CONTROLLER
#endif

#ifdef VMWARE_ESX_40_DDK

/**
 *      skb_copy_expand -       copy and expand sk_buff
 *      @skb: buffer to copy
 *      @newheadroom: new free bytes at head
 *      @newtailroom: new free bytes at tail
 *      @gfp_mask: allocation priority
 *
 *      Make a copy of both an &sk_buff and its data and while doing so
 *      allocate additional space.
 *
 *      This is used when the caller wishes to modify the data and needs a
 *      private copy of the data to alter as well as more space for new fields.
 *      Returns %NULL on failure or the pointer to the buffer
 *      on success. The returned buffer has a reference count of 1.
 *
 *      You must pass %GFP_ATOMIC as the allocation priority if this function
 *      is called from an interrupt.
 */
struct sk_buff *skb_copy_expand(const struct sk_buff *skb,
                                int newheadroom, int newtailroom,
                                gfp_t gfp_mask)
{
	int rc;
	struct sk_buff *new_skb = skb_copy((struct sk_buff *) skb, gfp_mask);

	if(new_skb == NULL)
		return NULL;

	rc = pskb_expand_head(new_skb, newheadroom, newtailroom, gfp_mask);

	if(rc != 0)
		return NULL;

	return new_skb;
}

void *memmove(void *dest, const void *src, size_t count)
{
	if (dest < src) {
		return memcpy(dest, src, count);
	} else {
		char *p = dest + count;
		const char *s = src + count;
		while (count--)
			*--p = *--s;
	}
	return dest;
}


#endif
