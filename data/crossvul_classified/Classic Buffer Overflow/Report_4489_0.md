# CrossVul Fix Pair: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') in c
**Pair ID:** 4489_0
**Vulnerability Class:** Classic Buffer Overflow
**CWE:** CWE-120
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4489_0`)

## Vulnerability Information & PoC

## Description
Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') - A buffer overflow condition exists when a product attempts to put more data in a buffer than it can hold, or when it attempts to put data in a memory area outside of the boundaries of a buffer.

## Vulnerable Code
```c
Lines 860-900 of the vulnerable file.

	if (!adapter)
		return -1;

	cmd->command = cpu_to_le16(HostCmd_CMD_802_11_AD_HOC_START);

	bss_desc = &priv->curr_bss_params.bss_descriptor;
	priv->attempted_bss_desc = bss_desc;

	/*
	 * Fill in the parameters for 2 data structures:
	 *   1. struct host_cmd_ds_802_11_ad_hoc_start command
	 *   2. bss_desc
	 * Driver will fill up SSID, bss_mode,IBSS param, Physical Param,
	 * probe delay, and Cap info.
	 * Firmware will fill up beacon period, Basic rates
	 * and operational rates.
	 */

	memset(adhoc_start->ssid, 0, IEEE80211_MAX_SSID_LEN);

	memcpy(adhoc_start->ssid, req_ssid->ssid, req_ssid->ssid_len);

	mwifiex_dbg(adapter, INFO, "info: ADHOC_S_CMD: SSID = %s\n",
		    adhoc_start->ssid);

	memset(bss_desc->ssid.ssid, 0, IEEE80211_MAX_SSID_LEN);
	memcpy(bss_desc->ssid.ssid, req_ssid->ssid, req_ssid->ssid_len);

	bss_desc->ssid.ssid_len = req_ssid->ssid_len;

	/* Set the BSS mode */
	adhoc_start->bss_mode = HostCmd_BSS_MODE_IBSS;
	bss_desc->bss_mode = NL80211_IFTYPE_ADHOC;
	adhoc_start->beacon_period = cpu_to_le16(priv->beacon_period);
	bss_desc->beacon_period = priv->beacon_period;

	/* Set Physical param set */
/* Parameter IE Id */
#define DS_PARA_IE_ID   3
/* Parameter IE length */
#define DS_PARA_IE_LEN  1
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -877,6 +877,8 @@
 
 	memset(adhoc_start->ssid, 0, IEEE80211_MAX_SSID_LEN);
 
+	if (req_ssid->ssid_len > IEEE80211_MAX_SSID_LEN)
+		req_ssid->ssid_len = IEEE80211_MAX_SSID_LEN;
 	memcpy(adhoc_start->ssid, req_ssid->ssid, req_ssid->ssid_len);
 
 	mwifiex_dbg(adapter, INFO, "info: ADHOC_S_CMD: SSID = %s\n",
```
