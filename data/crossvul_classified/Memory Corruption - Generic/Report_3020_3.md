# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 3020_3
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3020_3`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 764-804 of the vulnerable file.

{
	char *buff = (char *)data;
	u32 i;

	if (stringset != ETH_SS_STATS)
		return;

	for (i = 0; i < ARRAY_SIZE(g_xgmac_stats_string); i++) {
		snprintf(buff, ETH_GSTRING_LEN, g_xgmac_stats_string[i].desc);
		buff = buff + ETH_GSTRING_LEN;
	}
}

/**
 *hns_xgmac_get_sset_count - get xgmac string set count
 *@stringset: type of values in data
 *return xgmac string set count
 */
static int hns_xgmac_get_sset_count(int stringset)
{
	if (stringset == ETH_SS_STATS)
		return ARRAY_SIZE(g_xgmac_stats_string);

	return 0;
}

/**
 *hns_xgmac_get_regs_count - get xgmac regs count
 *return xgmac regs count
 */
static int hns_xgmac_get_regs_count(void)
{
	return HNS_XGMAC_DUMP_NUM;
}

void *hns_xgmac_config(struct hns_mac_cb *mac_cb, struct mac_params *mac_param)
{
	struct mac_driver *mac_drv;

	mac_drv = devm_kzalloc(mac_cb->dev, sizeof(*mac_drv), GFP_KERNEL);
	if (!mac_drv)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -781,7 +781,7 @@
  */
 static int hns_xgmac_get_sset_count(int stringset)
 {
-	if (stringset == ETH_SS_STATS)
+	if (stringset == ETH_SS_STATS || stringset == ETH_SS_PRIV_FLAGS)
 		return ARRAY_SIZE(g_xgmac_stats_string);
 
 	return 0;
```
