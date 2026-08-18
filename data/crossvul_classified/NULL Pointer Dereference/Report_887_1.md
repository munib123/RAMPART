# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 887_1
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `887_1`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 515-558 of the vulnerable file.

	mutex_lock(&local->sdp_lock);

	ssap = find_first_zero_bit(&local->local_sdp, LLCP_SDP_NUM_SAP);
	if (ssap == LLCP_SDP_NUM_SAP) {
		mutex_unlock(&local->sdp_lock);

		return LLCP_SAP_MAX;
	}

	pr_debug("SDP ssap %d\n", LLCP_WKS_NUM_SAP + ssap);

	set_bit(ssap, &local->local_sdp);

	mutex_unlock(&local->sdp_lock);

	return LLCP_WKS_NUM_SAP + ssap;
}

static int nfc_llcp_build_gb(struct nfc_llcp_local *local)
{
	u8 *gb_cur, *version_tlv, version, version_length;
	u8 *lto_tlv, lto_length;
	u8 *wks_tlv, wks_length;
	u8 *miux_tlv, miux_length;
	__be16 wks = cpu_to_be16(local->local_wks);
	u8 gb_len = 0;
	int ret = 0;

	version = LLCP_VERSION_11;
	version_tlv = nfc_llcp_build_tlv(LLCP_TLV_VERSION, &version,
					 1, &version_length);
	gb_len += version_length;

	lto_tlv = nfc_llcp_build_tlv(LLCP_TLV_LTO, &local->lto, 1, &lto_length);
	gb_len += lto_length;

	pr_debug("Local wks 0x%lx\n", local->local_wks);
	wks_tlv = nfc_llcp_build_tlv(LLCP_TLV_WKS, (u8 *)&wks, 2, &wks_length);
	gb_len += wks_length;

	miux_tlv = nfc_llcp_build_tlv(LLCP_TLV_MIUX, (u8 *)&local->miux, 0,
				      &miux_length);
	gb_len += miux_length;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -532,10 +532,10 @@
 
 static int nfc_llcp_build_gb(struct nfc_llcp_local *local)
 {
-	u8 *gb_cur, *version_tlv, version, version_length;
-	u8 *lto_tlv, lto_length;
-	u8 *wks_tlv, wks_length;
-	u8 *miux_tlv, miux_length;
+	u8 *gb_cur, version, version_length;
+	u8 lto_length, wks_length, miux_length;
+	u8 *version_tlv = NULL, *lto_tlv = NULL,
+	   *wks_tlv = NULL, *miux_tlv = NULL;
 	__be16 wks = cpu_to_be16(local->local_wks);
 	u8 gb_len = 0;
 	int ret = 0;
@@ -543,17 +543,33 @@
 	version = LLCP_VERSION_11;
 	version_tlv = nfc_llcp_build_tlv(LLCP_TLV_VERSION, &version,
 					 1, &version_length);
+	if (!version_tlv) {
+		ret = -ENOMEM;
+		goto out;
+	}
 	gb_len += version_length;
 
 	lto_tlv = nfc_llcp_build_tlv(LLCP_TLV_LTO, &local->lto, 1, &lto_length);
+	if (!lto_tlv) {
+		ret = -ENOMEM;
+		goto out;
+	}
 	gb_len += lto_length;
 
 	pr_debug("Local wks 0x%lx\n", local->local_wks);
 	wks_tlv = nfc_llcp_build_tlv(LLCP_TLV_WKS, (u8 *)&wks, 2, &wks_length);
+	if (!wks_tlv) {
+		ret = -ENOMEM;
+		goto out;
+	}
 	gb_len += wks_length;
 
 	miux_tlv = nfc_llcp_build_tlv(LLCP_TLV_MIUX, (u8 *)&local->miux, 0,
 				      &miux_length);
+	if (!miux_tlv) {
+		ret = -ENOMEM;
+		goto out;
+	}
 	gb_len += miux_length;
 
 	gb_len += ARRAY_SIZE(llcp_magic);
```
