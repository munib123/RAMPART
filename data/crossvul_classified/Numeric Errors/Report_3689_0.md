# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 3689_0
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3689_0`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 1366-1406 of the vulnerable file.

 * NIC startup/shutdown
 *
 *************************************************************************/

static int efx_probe_all(struct efx_nic *efx)
{
	int rc;

	rc = efx_probe_nic(efx);
	if (rc) {
		netif_err(efx, probe, efx->net_dev, "failed to create NIC\n");
		goto fail1;
	}

	rc = efx_probe_port(efx);
	if (rc) {
		netif_err(efx, probe, efx->net_dev, "failed to create port\n");
		goto fail2;
	}

	efx->rxq_entries = efx->txq_entries = EFX_DEFAULT_DMAQ_SIZE;
	rc = efx_probe_channels(efx);
	if (rc)
		goto fail3;

	rc = efx_probe_filters(efx);
	if (rc) {
		netif_err(efx, probe, efx->net_dev,
			  "failed to create filter tables\n");
		goto fail4;
	}

	return 0;

 fail4:
	efx_remove_channels(efx);
 fail3:
	efx_remove_port(efx);
 fail2:
	efx_remove_nic(efx);
 fail1:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1383,6 +1383,11 @@
 		goto fail2;
 	}
 
+	BUILD_BUG_ON(EFX_DEFAULT_DMAQ_SIZE < EFX_RXQ_MIN_ENT);
+	if (WARN_ON(EFX_DEFAULT_DMAQ_SIZE < EFX_TXQ_MIN_ENT(efx))) {
+		rc = -EINVAL;
+		goto fail3;
+	}
 	efx->rxq_entries = efx->txq_entries = EFX_DEFAULT_DMAQ_SIZE;
 	rc = efx_probe_channels(efx);
 	if (rc)
@@ -1973,6 +1978,7 @@
 	net_dev->irq = efx->pci_dev->irq;
 	net_dev->netdev_ops = &efx_netdev_ops;
 	SET_ETHTOOL_OPS(net_dev, &efx_ethtool_ops);
+	net_dev->gso_max_segs = EFX_TSO_MAX_SEGS;
 
 	/* Clear MAC statistics */
 	efx->mac_op->update_stats(efx);
```
