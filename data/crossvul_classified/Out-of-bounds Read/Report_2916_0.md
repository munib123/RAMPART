# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2916_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2916_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 943-983 of the vulnerable file.

	/* Now let's get the whole BOS descriptor set */
	buffer = kzalloc(total_len, GFP_KERNEL);
	if (!buffer) {
		ret = -ENOMEM;
		goto err;
	}
	dev->bos->desc = (struct usb_bos_descriptor *)buffer;

	ret = usb_get_descriptor(dev, USB_DT_BOS, 0, buffer, total_len);
	if (ret < total_len) {
		dev_err(ddev, "unable to get BOS descriptor set\n");
		if (ret >= 0)
			ret = -ENOMSG;
		goto err;
	}
	total_len -= length;

	for (i = 0; i < num; i++) {
		buffer += length;
		cap = (struct usb_dev_cap_header *)buffer;
		length = cap->bLength;

		if (total_len < length)
			break;
		total_len -= length;

		if (cap->bDescriptorType != USB_DT_DEVICE_CAPABILITY) {
			dev_warn(ddev, "descriptor type invalid, skip\n");
			continue;
		}

		switch (cap->bDevCapabilityType) {
		case USB_CAP_TYPE_WIRELESS_USB:
			/* Wireless USB cap descriptor is handled by wusb */
			break;
		case USB_CAP_TYPE_EXT:
			dev->bos->ext_cap =
				(struct usb_ext_cap_descriptor *)buffer;
			break;
		case USB_SS_CAP_TYPE:
			dev->bos->ss_cap =
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -960,10 +960,12 @@
 	for (i = 0; i < num; i++) {
 		buffer += length;
 		cap = (struct usb_dev_cap_header *)buffer;
+
+		if (total_len < sizeof(*cap) || total_len < cap->bLength) {
+			dev->bos->desc->bNumDeviceCaps = i;
+			break;
+		}
 		length = cap->bLength;
-
-		if (total_len < length)
-			break;
 		total_len -= length;
 
 		if (cap->bDescriptorType != USB_DT_DEVICE_CAPABILITY) {
```
