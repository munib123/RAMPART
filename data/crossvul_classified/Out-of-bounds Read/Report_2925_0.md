# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2925_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2925_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1618-1658 of the vulnerable file.

			  pcu->urb_ctrl_buf, pcu->ctrl_dma);
}

static const struct usb_cdc_union_desc *
ims_pcu_get_cdc_union_desc(struct usb_interface *intf)
{
	const void *buf = intf->altsetting->extra;
	size_t buflen = intf->altsetting->extralen;
	struct usb_cdc_union_desc *union_desc;

	if (!buf) {
		dev_err(&intf->dev, "Missing descriptor data\n");
		return NULL;
	}

	if (!buflen) {
		dev_err(&intf->dev, "Zero length descriptor\n");
		return NULL;
	}

	while (buflen > 0) {
		union_desc = (struct usb_cdc_union_desc *)buf;

		if (union_desc->bDescriptorType == USB_DT_CS_INTERFACE &&
		    union_desc->bDescriptorSubType == USB_CDC_UNION_TYPE) {
			dev_dbg(&intf->dev, "Found union header\n");
			return union_desc;
		}

		buflen -= union_desc->bLength;
		buf += union_desc->bLength;
	}

	dev_err(&intf->dev, "Missing CDC union descriptor\n");
	return NULL;
}

static int ims_pcu_parse_cdc_data(struct usb_interface *intf, struct ims_pcu *pcu)
{
	const struct usb_cdc_union_desc *union_desc;
	struct usb_host_interface *alt;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1635,13 +1635,25 @@
 		return NULL;
 	}
 
-	while (buflen > 0) {
+	while (buflen >= sizeof(*union_desc)) {
 		union_desc = (struct usb_cdc_union_desc *)buf;
+
+		if (union_desc->bLength > buflen) {
+			dev_err(&intf->dev, "Too large descriptor\n");
+			return NULL;
+		}
 
 		if (union_desc->bDescriptorType == USB_DT_CS_INTERFACE &&
 		    union_desc->bDescriptorSubType == USB_CDC_UNION_TYPE) {
 			dev_dbg(&intf->dev, "Found union header\n");
-			return union_desc;
+
+			if (union_desc->bLength >= sizeof(*union_desc))
+				return union_desc;
+
+			dev_err(&intf->dev,
+				"Union descriptor to short (%d vs %zd\n)",
+				union_desc->bLength, sizeof(*union_desc));
+			return NULL;
 		}
 
 		buflen -= union_desc->bLength;
```
