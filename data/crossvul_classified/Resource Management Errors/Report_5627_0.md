# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 5627_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5627_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 170-210 of the vulnerable file.

		skb->ip_summed = rcv_priv->ip_summed;

	length = skb->len + ETH_HLEN;
	if (dev_forward_skb(rcv, skb) != NET_RX_SUCCESS)
		goto rx_drop;

	stats->tx_bytes += length;
	stats->tx_packets++;

	rcv_stats->rx_bytes += length;
	rcv_stats->rx_packets++;

	return NETDEV_TX_OK;

tx_drop:
	kfree_skb(skb);
	stats->tx_dropped++;
	return NETDEV_TX_OK;

rx_drop:
	kfree_skb(skb);
	rcv_stats->rx_dropped++;
	return NETDEV_TX_OK;
}

/*
 * general routines
 */

static struct net_device_stats *veth_get_stats(struct net_device *dev)
{
	struct veth_priv *priv;
	int cpu;
	struct veth_net_stats *stats, total = {0};

	priv = netdev_priv(dev);

	for_each_possible_cpu(cpu) {
		stats = per_cpu_ptr(priv->stats, cpu);

		total.rx_packets += stats->rx_packets;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -187,7 +187,6 @@
 	return NETDEV_TX_OK;
 
 rx_drop:
-	kfree_skb(skb);
 	rcv_stats->rx_dropped++;
 	return NETDEV_TX_OK;
 }
```
