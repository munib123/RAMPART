# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 3689_4
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3689_4`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 96-136 of the vulnerable file.

	}
}


static inline unsigned
efx_max_tx_len(struct efx_nic *efx, dma_addr_t dma_addr)
{
	/* Depending on the NIC revision, we can use descriptor
	 * lengths up to 8K or 8K-1.  However, since PCI Express
	 * devices must split read requests at 4K boundaries, there is
	 * little benefit from using descriptors that cross those
	 * boundaries and we keep things simple by not doing so.
	 */
	unsigned len = (~dma_addr & 0xfff) + 1;

	/* Work around hardware bug for unaligned buffers. */
	if (EFX_WORKAROUND_5391(efx) && (dma_addr & 0xf))
		len = min_t(unsigned, len, 512 - (dma_addr & 0xf));

	return len;
}

/*
 * Add a socket buffer to a TX queue
 *
 * This maps all fragments of a socket buffer for DMA and adds them to
 * the TX queue.  The queue's insert pointer will be incremented by
 * the number of fragments in the socket buffer.
 *
 * If any DMA mapping fails, any mapped fragments will be unmapped,
 * the queue's insert pointer will be restored to its original value.
 *
 * This function is split out from efx_hard_start_xmit to allow the
 * loopback test to direct packets via specific TX queues.
 *
 * Returns NETDEV_TX_OK or NETDEV_TX_BUSY
 * You must hold netif_tx_lock() to call this function.
 */
netdev_tx_t efx_enqueue_skb(struct efx_tx_queue *tx_queue, struct sk_buff *skb)
{
	struct efx_nic *efx = tx_queue->efx;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -113,6 +113,25 @@
 		len = min_t(unsigned, len, 512 - (dma_addr & 0xf));
 
 	return len;
+}
+
+unsigned int efx_tx_max_skb_descs(struct efx_nic *efx)
+{
+	/* Header and payload descriptor for each output segment, plus
+	 * one for every input fragment boundary within a segment
+	 */
+	unsigned int max_descs = EFX_TSO_MAX_SEGS * 2 + MAX_SKB_FRAGS;
+
+	/* Possibly one more per segment for the alignment workaround */
+	if (EFX_WORKAROUND_5391(efx))
+		max_descs += EFX_TSO_MAX_SEGS;
+
+	/* Possibly more for PCIe page boundaries within input fragments */
+	if (PAGE_SIZE > EFX_PAGE_SIZE)
+		max_descs += max_t(unsigned int, MAX_SKB_FRAGS,
+				   DIV_ROUND_UP(GSO_MAX_SIZE, EFX_PAGE_SIZE));
+
+	return max_descs;
 }
 
 /*
```
