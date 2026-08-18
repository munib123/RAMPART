# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 1246_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1246_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 1012-1052 of the vulnerable file.

	return 0;
}

/*
 * This function allocates a buffer for CMDRSP
 */
static int mwifiex_pcie_alloc_cmdrsp_buf(struct mwifiex_adapter *adapter)
{
	struct pcie_service_card *card = adapter->card;
	struct sk_buff *skb;

	/* Allocate memory for receiving command response data */
	skb = dev_alloc_skb(MWIFIEX_UPLD_SIZE);
	if (!skb) {
		mwifiex_dbg(adapter, ERROR,
			    "Unable to allocate skb for command response data.\n");
		return -ENOMEM;
	}
	skb_put(skb, MWIFIEX_UPLD_SIZE);
	if (mwifiex_map_pci_memory(adapter, skb, MWIFIEX_UPLD_SIZE,
				   PCI_DMA_FROMDEVICE))
		return -1;

	card->cmdrsp_buf = skb;

	return 0;
}

/*
 * This function deletes a buffer for CMDRSP
 */
static int mwifiex_pcie_delete_cmdrsp_buf(struct mwifiex_adapter *adapter)
{
	struct pcie_service_card *card;

	if (!adapter)
		return 0;

	card = adapter->card;

	if (card && card->cmdrsp_buf) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1029,8 +1029,10 @@
 	}
 	skb_put(skb, MWIFIEX_UPLD_SIZE);
 	if (mwifiex_map_pci_memory(adapter, skb, MWIFIEX_UPLD_SIZE,
-				   PCI_DMA_FROMDEVICE))
+				   PCI_DMA_FROMDEVICE)) {
+		kfree_skb(skb);
 		return -1;
+	}
 
 	card->cmdrsp_buf = skb;
 
```
