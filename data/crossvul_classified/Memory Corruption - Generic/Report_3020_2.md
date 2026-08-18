# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 3020_2
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3020_2`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 859-899 of the vulnerable file.

	regs_buff[17] = queue->rx_ring.stats.rx_bytes;
	regs_buff[18] = queue->rx_ring.stats.rx_err_cnt;
	regs_buff[19] = queue->rx_ring.stats.io_err_cnt;
	regs_buff[20] = queue->rx_ring.stats.sw_err_cnt;
	regs_buff[21] = queue->rx_ring.stats.seg_pkt_cnt;
	regs_buff[22] = queue->rx_ring.stats.reuse_pg_cnt;
	regs_buff[23] = queue->rx_ring.stats.err_pkt_len;
	regs_buff[24] = queue->rx_ring.stats.non_vld_descs;
	regs_buff[25] = queue->rx_ring.stats.err_bd_num;
	regs_buff[26] = queue->rx_ring.stats.l2_err;
	regs_buff[27] = queue->rx_ring.stats.l3l4_csum_err;
}

/**
 *hns_rcb_get_ring_sset_count - rcb string set count
 *@stringset:ethtool cmd
 *return rcb ring string set count
 */
int hns_rcb_get_ring_sset_count(int stringset)
{
	if (stringset == ETH_SS_STATS)
		return HNS_RING_STATIC_REG_NUM;

	return 0;
}

/**
 *hns_rcb_get_common_regs_count - rcb common regs count
 *return regs count
 */
int hns_rcb_get_common_regs_count(void)
{
	return HNS_RCB_COMMON_DUMP_REG_NUM;
}

/**
 *rcb_get_sset_count - rcb ring regs count
 *return regs count
 */
int hns_rcb_get_ring_regs_count(void)
{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -876,7 +876,7 @@
  */
 int hns_rcb_get_ring_sset_count(int stringset)
 {
-	if (stringset == ETH_SS_STATS)
+	if (stringset == ETH_SS_STATS || stringset == ETH_SS_PRIV_FLAGS)
 		return HNS_RING_STATIC_REG_NUM;
 
 	return 0;
```
