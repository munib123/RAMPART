# CrossVul Fix Pair: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') in c
**Pair ID:** 998_0
**Vulnerability Class:** Classic Buffer Overflow
**CWE:** CWE-120
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `998_0`)

## Vulnerability Information & PoC

## Description
Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') - A buffer overflow condition exists when a product attempts to put more data in a buffer than it can hold, or when it attempts to put data in a memory area outside of the boundaries of a buffer.

## Vulnerable Code
```c
Lines 224-264 of the vulnerable file.

 */
static int mwifiex_update_vs_ie(const u8 *ies, int ies_len,
				struct mwifiex_ie **ie_ptr, u16 mask,
				unsigned int oui, u8 oui_type)
{
	struct ieee_types_header *vs_ie;
	struct mwifiex_ie *ie = *ie_ptr;
	const u8 *vendor_ie;

	vendor_ie = cfg80211_find_vendor_ie(oui, oui_type, ies, ies_len);
	if (vendor_ie) {
		if (!*ie_ptr) {
			*ie_ptr = kzalloc(sizeof(struct mwifiex_ie),
					  GFP_KERNEL);
			if (!*ie_ptr)
				return -ENOMEM;
			ie = *ie_ptr;
		}

		vs_ie = (struct ieee_types_header *)vendor_ie;
		memcpy(ie->ie_buffer + le16_to_cpu(ie->ie_length),
		       vs_ie, vs_ie->len + 2);
		le16_unaligned_add_cpu(&ie->ie_length, vs_ie->len + 2);
		ie->mgmt_subtype_mask = cpu_to_le16(mask);
		ie->ie_index = cpu_to_le16(MWIFIEX_AUTO_IDX_MASK);
	}

	*ie_ptr = ie;
	return 0;
}

/* This function parses beacon IEs, probe response IEs, association response IEs
 * from cfg80211_ap_settings->beacon and sets these IE to FW.
 */
static int mwifiex_set_mgmt_beacon_data_ies(struct mwifiex_private *priv,
					    struct cfg80211_beacon_data *data)
{
	struct mwifiex_ie *beacon_ie = NULL, *pr_ie = NULL, *ar_ie = NULL;
	u16 beacon_idx = MWIFIEX_AUTO_IDX_MASK, pr_idx = MWIFIEX_AUTO_IDX_MASK;
	u16 ar_idx = MWIFIEX_AUTO_IDX_MASK;
	int ret = 0;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -241,6 +241,9 @@
 		}
 
 		vs_ie = (struct ieee_types_header *)vendor_ie;
+		if (le16_to_cpu(ie->ie_length) + vs_ie->len + 2 >
+			IEEE_MAX_IE_SIZE)
+			return -EINVAL;
 		memcpy(ie->ie_buffer + le16_to_cpu(ie->ie_length),
 		       vs_ie, vs_ie->len + 2);
 		le16_unaligned_add_cpu(&ie->ie_length, vs_ie->len + 2);
```
