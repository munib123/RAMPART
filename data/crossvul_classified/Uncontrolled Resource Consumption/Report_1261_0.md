# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 1261_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1261_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 1739-1779 of the vulnerable file.


	return rsi_send_internal_mgmt_frame(common, skb);
}

static int rsi_send_beacon(struct rsi_common *common)
{
	struct sk_buff *skb = NULL;
	u8 dword_align_bytes = 0;

	skb = dev_alloc_skb(MAX_MGMT_PKT_SIZE);
	if (!skb)
		return -ENOMEM;

	memset(skb->data, 0, MAX_MGMT_PKT_SIZE);

	dword_align_bytes = ((unsigned long)skb->data & 0x3f);
	if (dword_align_bytes)
		skb_pull(skb, (64 - dword_align_bytes));
	if (rsi_prepare_beacon(common, skb)) {
		rsi_dbg(ERR_ZONE, "Failed to prepare beacon\n");
		return -EINVAL;
	}
	skb_queue_tail(&common->tx_queue[MGMT_BEACON_Q], skb);
	rsi_set_event(&common->tx_thread.event);
	rsi_dbg(DATA_TX_ZONE, "%s: Added to beacon queue\n", __func__);

	return 0;
}

#ifdef CONFIG_PM
int rsi_send_wowlan_request(struct rsi_common *common, u16 flags,
			    u16 sleep_status)
{
	struct rsi_wowlan_req *cmd_frame;
	struct sk_buff *skb;
	u8 length;

	rsi_dbg(ERR_ZONE, "%s: Sending wowlan request frame\n", __func__);

	length = sizeof(*cmd_frame);
	skb = dev_alloc_skb(length);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1756,6 +1756,7 @@
 		skb_pull(skb, (64 - dword_align_bytes));
 	if (rsi_prepare_beacon(common, skb)) {
 		rsi_dbg(ERR_ZONE, "Failed to prepare beacon\n");
+		dev_kfree_skb(skb);
 		return -EINVAL;
 	}
 	skb_queue_tail(&common->tx_queue[MGMT_BEACON_Q], skb);
```
