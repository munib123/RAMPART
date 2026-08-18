# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 3018_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3018_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 283-325 of the vulnerable file.

	int sizeoflast;
	int k;

	frag_buf_num = (size + BD_MAX_SEND_SIZE - 1) / BD_MAX_SEND_SIZE;
	sizeoflast = size % BD_MAX_SEND_SIZE;
	sizeoflast = sizeoflast ? sizeoflast : BD_MAX_SEND_SIZE;

	/* when the frag size is bigger than hardware, split this frag */
	for (k = 0; k < frag_buf_num; k++)
		fill_v2_desc(ring, priv,
			     (k == frag_buf_num - 1) ?
					sizeoflast : BD_MAX_SEND_SIZE,
			     dma + BD_MAX_SEND_SIZE * k,
			     frag_end && (k == frag_buf_num - 1) ? 1 : 0,
			     buf_num,
			     (type == DESC_TYPE_SKB && !k) ?
					DESC_TYPE_SKB : DESC_TYPE_PAGE,
			     mtu);
}

int hns_nic_net_xmit_hw(struct net_device *ndev,
			struct sk_buff *skb,
			struct hns_nic_ring_data *ring_data)
{
	struct hns_nic_priv *priv = netdev_priv(ndev);
	struct hnae_ring *ring = ring_data->ring;
	struct device *dev = ring_to_dev(ring);
	struct netdev_queue *dev_queue;
	struct skb_frag_struct *frag;
	int buf_num;
	int seg_num;
	dma_addr_t dma;
	int size, next_to_use;
	int i;

	switch (priv->ops.maybe_stop_tx(&skb, &buf_num, ring)) {
	case -EBUSY:
		ring->stats.tx_busy++;
		goto out_net_tx_busy;
	case -ENOMEM:
		ring->stats.sw_err_cnt++;
		netdev_err(ndev, "no memory to xmit!\n");
		goto out_err_tx_ok;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -300,9 +300,9 @@
 			     mtu);
 }
 
-int hns_nic_net_xmit_hw(struct net_device *ndev,
-			struct sk_buff *skb,
-			struct hns_nic_ring_data *ring_data)
+netdev_tx_t hns_nic_net_xmit_hw(struct net_device *ndev,
+				struct sk_buff *skb,
+				struct hns_nic_ring_data *ring_data)
 {
 	struct hns_nic_priv *priv = netdev_priv(ndev);
 	struct hnae_ring *ring = ring_data->ring;
@@ -360,6 +360,10 @@
 	/*complete translate all packets*/
 	dev_queue = netdev_get_tx_queue(ndev, skb->queue_mapping);
 	netdev_tx_sent_queue(dev_queue, skb->len);
+
+	netif_trans_update(ndev);
+	ndev->stats.tx_bytes += skb->len;
+	ndev->stats.tx_packets++;
 
 	wmb(); /* commit all data before submit */
 	assert(skb->queue_mapping < priv->ae_handle->q_num);
@@ -1469,17 +1473,11 @@
 				    struct net_device *ndev)
 {
 	struct hns_nic_priv *priv = netdev_priv(ndev);
-	int ret;
 
 	assert(skb->queue_mapping < ndev->ae_handle->q_num);
-	ret = hns_nic_net_xmit_hw(ndev, skb,
-				  &tx_ring_data(priv, skb->queue_mapping));
-	if (ret == NETDEV_TX_OK) {
-		netif_trans_update(ndev);
-		ndev->stats.tx_bytes += skb->len;
-		ndev->stats.tx_packets++;
-	}
-	return (netdev_tx_t)ret;
+
+	return hns_nic_net_xmit_hw(ndev, skb,
+				   &tx_ring_data(priv, skb->queue_mapping));
 }
 
 static void hns_nic_drop_rx_fetch(struct hns_nic_ring_data *ring_data,
```
