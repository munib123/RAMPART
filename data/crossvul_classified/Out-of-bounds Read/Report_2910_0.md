# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2910_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2910_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 204-244 of the vulnerable file.

	}

	if (! snd_usb_parse_audio_interface(chip, interface)) {
		usb_set_interface(dev, interface, 0); /* reset the current interface */
		usb_driver_claim_interface(&usb_audio_driver, iface, (void *)-1L);
	}

	return 0;
}

/*
 * parse audio control descriptor and create pcm/midi streams
 */
static int snd_usb_create_streams(struct snd_usb_audio *chip, int ctrlif)
{
	struct usb_device *dev = chip->dev;
	struct usb_host_interface *host_iface;
	struct usb_interface_descriptor *altsd;
	void *control_header;
	int i, protocol;

	/* find audiocontrol interface */
	host_iface = &usb_ifnum_to_if(dev, ctrlif)->altsetting[0];
	control_header = snd_usb_find_csint_desc(host_iface->extra,
						 host_iface->extralen,
						 NULL, UAC_HEADER);
	altsd = get_iface_desc(host_iface);
	protocol = altsd->bInterfaceProtocol;

	if (!control_header) {
		dev_err(&dev->dev, "cannot find UAC_HEADER\n");
		return -EINVAL;
	}

	switch (protocol) {
	default:
		dev_warn(&dev->dev,
			 "unknown interface protocol %#02x, assuming v1\n",
			 protocol);
		/* fall through */

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -221,6 +221,7 @@
 	struct usb_interface_descriptor *altsd;
 	void *control_header;
 	int i, protocol;
+	int rest_bytes;
 
 	/* find audiocontrol interface */
 	host_iface = &usb_ifnum_to_if(dev, ctrlif)->altsetting[0];
@@ -235,6 +236,15 @@
 		return -EINVAL;
 	}
 
+	rest_bytes = (void *)(host_iface->extra + host_iface->extralen) -
+		control_header;
+
+	/* just to be sure -- this shouldn't hit at all */
+	if (rest_bytes <= 0) {
+		dev_err(&dev->dev, "invalid control header\n");
+		return -EINVAL;
+	}
+
 	switch (protocol) {
 	default:
 		dev_warn(&dev->dev,
@@ -245,8 +255,18 @@
 	case UAC_VERSION_1: {
 		struct uac1_ac_header_descriptor *h1 = control_header;
 
+		if (rest_bytes < sizeof(*h1)) {
+			dev_err(&dev->dev, "too short v1 buffer descriptor\n");
+			return -EINVAL;
+		}
+
 		if (!h1->bInCollection) {
 			dev_info(&dev->dev, "skipping empty audio interface (v1)\n");
+			return -EINVAL;
+		}
+
+		if (rest_bytes < h1->bLength) {
+			dev_err(&dev->dev, "invalid buffer length (v1)\n");
 			return -EINVAL;
 		}
 
```
