# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5544_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5544_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 326-366 of the vulnerable file.

	disable_irq(vif->irq);

	xenvif_get(vif);

	rtnl_lock();
	if (!vif->can_sg && vif->dev->mtu > ETH_DATA_LEN)
		dev_set_mtu(vif->dev, ETH_DATA_LEN);
	netdev_update_features(vif->dev);
	netif_carrier_on(vif->dev);
	if (netif_running(vif->dev))
		xenvif_up(vif);
	rtnl_unlock();

	return 0;
err_unmap:
	xen_netbk_unmap_frontend_rings(vif);
err:
	return err;
}

void xenvif_disconnect(struct xenvif *vif)
{
	struct net_device *dev = vif->dev;
	if (netif_carrier_ok(dev)) {
		rtnl_lock();
		netif_carrier_off(dev); /* discard queued packets */
		if (netif_running(dev))
			xenvif_down(vif);
		rtnl_unlock();
		xenvif_put(vif);
	}

	atomic_dec(&vif->refcnt);
	wait_event(vif->waiting_to_free, atomic_read(&vif->refcnt) == 0);

	del_timer_sync(&vif->credit_timeout);

	if (vif->irq)
		unbind_from_irqhandler(vif->irq, vif);

	unregister_netdev(vif->dev);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -343,17 +343,22 @@
 	return err;
 }
 
+void xenvif_carrier_off(struct xenvif *vif)
+{
+	struct net_device *dev = vif->dev;
+
+	rtnl_lock();
+	netif_carrier_off(dev); /* discard queued packets */
+	if (netif_running(dev))
+		xenvif_down(vif);
+	rtnl_unlock();
+	xenvif_put(vif);
+}
+
 void xenvif_disconnect(struct xenvif *vif)
 {
-	struct net_device *dev = vif->dev;
-	if (netif_carrier_ok(dev)) {
-		rtnl_lock();
-		netif_carrier_off(dev); /* discard queued packets */
-		if (netif_running(dev))
-			xenvif_down(vif);
-		rtnl_unlock();
-		xenvif_put(vif);
-	}
+	if (netif_carrier_ok(vif->dev))
+		xenvif_carrier_off(vif);
 
 	atomic_dec(&vif->refcnt);
 	wait_event(vif->waiting_to_free, atomic_read(&vif->refcnt) == 0);
```
