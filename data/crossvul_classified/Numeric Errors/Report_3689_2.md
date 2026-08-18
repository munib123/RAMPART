# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 3689_2
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3689_2`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 673-713 of the vulnerable file.

		efx->type->push_irq_moderation(channel);

	return 0;
}

static void efx_ethtool_get_ringparam(struct net_device *net_dev,
				      struct ethtool_ringparam *ring)
{
	struct efx_nic *efx = netdev_priv(net_dev);

	ring->rx_max_pending = EFX_MAX_DMAQ_SIZE;
	ring->tx_max_pending = EFX_MAX_DMAQ_SIZE;
	ring->rx_pending = efx->rxq_entries;
	ring->tx_pending = efx->txq_entries;
}

static int efx_ethtool_set_ringparam(struct net_device *net_dev,
				     struct ethtool_ringparam *ring)
{
	struct efx_nic *efx = netdev_priv(net_dev);

	if (ring->rx_mini_pending || ring->rx_jumbo_pending ||
	    ring->rx_pending > EFX_MAX_DMAQ_SIZE ||
	    ring->tx_pending > EFX_MAX_DMAQ_SIZE)
		return -EINVAL;

	if (ring->rx_pending < EFX_MIN_RING_SIZE ||
	    ring->tx_pending < EFX_MIN_RING_SIZE) {
		netif_err(efx, drv, efx->net_dev,
			  "TX and RX queues cannot be smaller than %ld\n",
			  EFX_MIN_RING_SIZE);
		return -EINVAL;
	}

	return efx_realloc_channels(efx, ring->rx_pending, ring->tx_pending);
}

static int efx_ethtool_set_pauseparam(struct net_device *net_dev,
				      struct ethtool_pauseparam *pause)
{
	struct efx_nic *efx = netdev_priv(net_dev);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -690,21 +690,27 @@
 				     struct ethtool_ringparam *ring)
 {
 	struct efx_nic *efx = netdev_priv(net_dev);
+	u32 txq_entries;
 
 	if (ring->rx_mini_pending || ring->rx_jumbo_pending ||
 	    ring->rx_pending > EFX_MAX_DMAQ_SIZE ||
 	    ring->tx_pending > EFX_MAX_DMAQ_SIZE)
 		return -EINVAL;
 
-	if (ring->rx_pending < EFX_MIN_RING_SIZE ||
-	    ring->tx_pending < EFX_MIN_RING_SIZE) {
+	if (ring->rx_pending < EFX_RXQ_MIN_ENT) {
 		netif_err(efx, drv, efx->net_dev,
-			  "TX and RX queues cannot be smaller than %ld\n",
-			  EFX_MIN_RING_SIZE);
+			  "RX queues cannot be smaller than %u\n",
+			  EFX_RXQ_MIN_ENT);
 		return -EINVAL;
 	}
 
-	return efx_realloc_channels(efx, ring->rx_pending, ring->tx_pending);
+	txq_entries = max(ring->tx_pending, EFX_TXQ_MIN_ENT(efx));
+	if (txq_entries != ring->tx_pending)
+		netif_warn(efx, drv, efx->net_dev,
+			   "increasing TX queue size to minimum of %u\n",
+			   txq_entries);
+
+	return efx_realloc_channels(efx, ring->rx_pending, txq_entries);
 }
 
 static int efx_ethtool_set_pauseparam(struct net_device *net_dev,
```
