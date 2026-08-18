# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 3020_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3020_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 405-445 of the vulnerable file.

		+= dsaf_read_dev(ppe_cb, PPE_HIS_RX_APP_BUF_WAIT_CNT_REG);
	hw_stats->rx_drop_no_buf
		+= dsaf_read_dev(ppe_cb, PPE_HIS_RX_PKT_DROP_FUL_CNT_REG);
	hw_stats->rx_err_fifo_full
		+= dsaf_read_dev(ppe_cb, PPE_HIS_RX_PKT_DROP_PRT_CNT_REG);

	hw_stats->tx_bd_form_rcb
		+= dsaf_read_dev(ppe_cb, PPE_HIS_TX_BD_CNT_REG);
	hw_stats->tx_pkts_from_rcb
		+= dsaf_read_dev(ppe_cb, PPE_HIS_TX_PKT_CNT_REG);
	hw_stats->tx_pkts
		+= dsaf_read_dev(ppe_cb, PPE_HIS_TX_PKT_OK_CNT_REG);
	hw_stats->tx_err_fifo_empty
		+= dsaf_read_dev(ppe_cb, PPE_HIS_TX_PKT_EPT_CNT_REG);
	hw_stats->tx_err_checksum
		+= dsaf_read_dev(ppe_cb, PPE_HIS_TX_PKT_CS_FAIL_CNT_REG);
}

int hns_ppe_get_sset_count(int stringset)
{
	if (stringset == ETH_SS_STATS)
		return ETH_PPE_STATIC_NUM;
	return 0;
}

int hns_ppe_get_regs_count(void)
{
	return ETH_PPE_DUMP_NUM;
}

/**
 * ppe_get_strings - get ppe srting
 * @ppe_device: ppe device
 * @stringset: string set type
 * @data: output string
 */
void hns_ppe_get_strings(struct hns_ppe_cb *ppe_cb, int stringset, u8 *data)
{
	char *buff = (char *)data;
	int index = ppe_cb->index;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -422,7 +422,7 @@
 
 int hns_ppe_get_sset_count(int stringset)
 {
-	if (stringset == ETH_SS_STATS)
+	if (stringset == ETH_SS_STATS || stringset == ETH_SS_PRIV_FLAGS)
 		return ETH_PPE_STATIC_NUM;
 	return 0;
 }
```
