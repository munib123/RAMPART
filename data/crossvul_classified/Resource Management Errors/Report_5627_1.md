# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 5627_1
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5627_1`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 1434-1474 of the vulnerable file.

	atomic_dec(&netstamp_needed);
}
EXPORT_SYMBOL(net_disable_timestamp);

static inline void net_timestamp(struct sk_buff *skb)
{
	if (atomic_read(&netstamp_needed))
		__net_timestamp(skb);
	else
		skb->tstamp.tv64 = 0;
}

/**
 * dev_forward_skb - loopback an skb to another netif
 *
 * @dev: destination network device
 * @skb: buffer to forward
 *
 * return values:
 *	NET_RX_SUCCESS	(no congestion)
 *	NET_RX_DROP     (packet was dropped)
 *
 * dev_forward_skb can be used for injecting an skb from the
 * start_xmit function of one device into the receive queue
 * of another device.
 *
 * The receiving device may be in another namespace, so
 * we have to clear all information in the skb that could
 * impact namespace isolation.
 */
int dev_forward_skb(struct net_device *dev, struct sk_buff *skb)
{
	skb_orphan(skb);

	if (!(dev->flags & IFF_UP))
		return NET_RX_DROP;

	if (skb->len > (dev->mtu + dev->hard_header_len))
		return NET_RX_DROP;

	skb_set_dev(skb, dev);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1451,7 +1451,7 @@
  *
  * return values:
  *	NET_RX_SUCCESS	(no congestion)
- *	NET_RX_DROP     (packet was dropped)
+ *	NET_RX_DROP     (packet was dropped, but freed)
  *
  * dev_forward_skb can be used for injecting an skb from the
  * start_xmit function of one device into the receive queue
@@ -1465,12 +1465,11 @@
 {
 	skb_orphan(skb);
 
-	if (!(dev->flags & IFF_UP))
+	if (!(dev->flags & IFF_UP) ||
+	    (skb->len > (dev->mtu + dev->hard_header_len))) {
+		kfree_skb(skb);
 		return NET_RX_DROP;
-
-	if (skb->len > (dev->mtu + dev->hard_header_len))
-		return NET_RX_DROP;
-
+	}
 	skb_set_dev(skb, dev);
 	skb->tstamp.tv64 = 0;
 	skb->pkt_type = PACKET_HOST;
```
