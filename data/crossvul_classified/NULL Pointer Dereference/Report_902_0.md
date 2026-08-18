# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 902_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `902_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 894-934 of the vulnerable file.

	if (!dev)
		return -ENODEV;

	target_idx = nla_get_u32(info->attrs[NFC_ATTR_TARGET_INDEX]);
	protocol = nla_get_u32(info->attrs[NFC_ATTR_PROTOCOLS]);

	nfc_deactivate_target(dev, target_idx, NFC_TARGET_MODE_SLEEP);
	rc = nfc_activate_target(dev, target_idx, protocol);

	nfc_put_device(dev);
	return rc;
}

static int nfc_genl_deactivate_target(struct sk_buff *skb,
				      struct genl_info *info)
{
	struct nfc_dev *dev;
	u32 device_idx, target_idx;
	int rc;

	if (!info->attrs[NFC_ATTR_DEVICE_INDEX])
		return -EINVAL;

	device_idx = nla_get_u32(info->attrs[NFC_ATTR_DEVICE_INDEX]);

	dev = nfc_get_device(device_idx);
	if (!dev)
		return -ENODEV;

	target_idx = nla_get_u32(info->attrs[NFC_ATTR_TARGET_INDEX]);

	rc = nfc_deactivate_target(dev, target_idx, NFC_TARGET_MODE_SLEEP);

	nfc_put_device(dev);
	return rc;
}

static int nfc_genl_dep_link_up(struct sk_buff *skb, struct genl_info *info)
{
	struct nfc_dev *dev;
	int rc, tgt_idx;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -911,7 +911,8 @@
 	u32 device_idx, target_idx;
 	int rc;
 
-	if (!info->attrs[NFC_ATTR_DEVICE_INDEX])
+	if (!info->attrs[NFC_ATTR_DEVICE_INDEX] ||
+	    !info->attrs[NFC_ATTR_TARGET_INDEX])
 		return -EINVAL;
 
 	device_idx = nla_get_u32(info->attrs[NFC_ATTR_DEVICE_INDEX]);
```
