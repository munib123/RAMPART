# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 3689_1
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3689_1`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 17-57 of the vulnerable file.

/* PCI IDs */
#define BETHPAGE_A_P_DEVID      0x0803
#define SIENA_A_P_DEVID         0x0813

/* Solarstorm controllers use BAR 0 for I/O space and BAR 2(&3) for memory */
#define EFX_MEM_BAR 2

/* TX */
extern int efx_probe_tx_queue(struct efx_tx_queue *tx_queue);
extern void efx_remove_tx_queue(struct efx_tx_queue *tx_queue);
extern void efx_init_tx_queue(struct efx_tx_queue *tx_queue);
extern void efx_init_tx_queue_core_txq(struct efx_tx_queue *tx_queue);
extern void efx_fini_tx_queue(struct efx_tx_queue *tx_queue);
extern void efx_release_tx_buffers(struct efx_tx_queue *tx_queue);
extern netdev_tx_t
efx_hard_start_xmit(struct sk_buff *skb, struct net_device *net_dev);
extern netdev_tx_t
efx_enqueue_skb(struct efx_tx_queue *tx_queue, struct sk_buff *skb);
extern void efx_xmit_done(struct efx_tx_queue *tx_queue, unsigned int index);
extern int efx_setup_tc(struct net_device *net_dev, u8 num_tc);

/* RX */
extern int efx_probe_rx_queue(struct efx_rx_queue *rx_queue);
extern void efx_remove_rx_queue(struct efx_rx_queue *rx_queue);
extern void efx_init_rx_queue(struct efx_rx_queue *rx_queue);
extern void efx_fini_rx_queue(struct efx_rx_queue *rx_queue);
extern void efx_rx_strategy(struct efx_channel *channel);
extern void efx_fast_push_rx_descriptors(struct efx_rx_queue *rx_queue);
extern void efx_rx_slow_fill(unsigned long context);
extern void __efx_rx_packet(struct efx_channel *channel,
			    struct efx_rx_buffer *rx_buf, bool checksummed);
extern void efx_rx_packet(struct efx_rx_queue *rx_queue, unsigned int index,
			  unsigned int len, bool checksummed, bool discard);
extern void efx_schedule_slow_fill(struct efx_rx_queue *rx_queue);

#define EFX_MAX_DMAQ_SIZE 4096UL
#define EFX_DEFAULT_DMAQ_SIZE 1024UL
#define EFX_MIN_DMAQ_SIZE 512UL

#define EFX_MAX_EVQ_SIZE 16384UL
#define EFX_MIN_EVQ_SIZE 512UL
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -34,6 +34,7 @@
 efx_enqueue_skb(struct efx_tx_queue *tx_queue, struct sk_buff *skb);
 extern void efx_xmit_done(struct efx_tx_queue *tx_queue, unsigned int index);
 extern int efx_setup_tc(struct net_device *net_dev, u8 num_tc);
+extern unsigned int efx_tx_max_skb_descs(struct efx_nic *efx);
 
 /* RX */
 extern int efx_probe_rx_queue(struct efx_rx_queue *rx_queue);
@@ -56,10 +57,15 @@
 #define EFX_MAX_EVQ_SIZE 16384UL
 #define EFX_MIN_EVQ_SIZE 512UL
 
-/* The smallest [rt]xq_entries that the driver supports. Callers of
- * efx_wake_queue() assume that they can subsequently send at least one
- * skb. Falcon/A1 may require up to three descriptors per skb_frag. */
-#define EFX_MIN_RING_SIZE (roundup_pow_of_two(2 * 3 * MAX_SKB_FRAGS))
+/* Maximum number of TCP segments we support for soft-TSO */
+#define EFX_TSO_MAX_SEGS	100
+
+/* The smallest [rt]xq_entries that the driver supports.  RX minimum
+ * is a bit arbitrary.  For TX, we must have space for at least 2
+ * TSO skbs.
+ */
+#define EFX_RXQ_MIN_ENT		128U
+#define EFX_TXQ_MIN_ENT(efx)	(2 * efx_tx_max_skb_descs(efx))
 
 /* Filters */
 extern int efx_probe_filters(struct efx_nic *efx);
```
