# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2914_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2914_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 958-998 of the vulnerable file.

static void hid_free_buffers(struct usb_device *dev, struct hid_device *hid)
{
	struct usbhid_device *usbhid = hid->driver_data;

	usb_free_coherent(dev, usbhid->bufsize, usbhid->inbuf, usbhid->inbuf_dma);
	usb_free_coherent(dev, usbhid->bufsize, usbhid->outbuf, usbhid->outbuf_dma);
	kfree(usbhid->cr);
	usb_free_coherent(dev, usbhid->bufsize, usbhid->ctrlbuf, usbhid->ctrlbuf_dma);
}

static int usbhid_parse(struct hid_device *hid)
{
	struct usb_interface *intf = to_usb_interface(hid->dev.parent);
	struct usb_host_interface *interface = intf->cur_altsetting;
	struct usb_device *dev = interface_to_usbdev (intf);
	struct hid_descriptor *hdesc;
	u32 quirks = 0;
	unsigned int rsize = 0;
	char *rdesc;
	int ret, n;

	quirks = usbhid_lookup_quirk(le16_to_cpu(dev->descriptor.idVendor),
			le16_to_cpu(dev->descriptor.idProduct));

	if (quirks & HID_QUIRK_IGNORE)
		return -ENODEV;

	/* Many keyboards and mice don't like to be polled for reports,
	 * so we will always set the HID_QUIRK_NOGET flag for them. */
	if (interface->desc.bInterfaceSubClass == USB_INTERFACE_SUBCLASS_BOOT) {
		if (interface->desc.bInterfaceProtocol == USB_INTERFACE_PROTOCOL_KEYBOARD ||
			interface->desc.bInterfaceProtocol == USB_INTERFACE_PROTOCOL_MOUSE)
				quirks |= HID_QUIRK_NOGET;
	}

	if (usb_get_extra_descriptor(interface, HID_DT_HID, &hdesc) &&
	    (!interface->desc.bNumEndpoints ||
	     usb_get_extra_descriptor(&interface->endpoint[0], HID_DT_HID, &hdesc))) {
		dbg_hid("class descriptor not present\n");
		return -ENODEV;
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -975,6 +975,8 @@
 	unsigned int rsize = 0;
 	char *rdesc;
 	int ret, n;
+	int num_descriptors;
+	size_t offset = offsetof(struct hid_descriptor, desc);
 
 	quirks = usbhid_lookup_quirk(le16_to_cpu(dev->descriptor.idVendor),
 			le16_to_cpu(dev->descriptor.idProduct));
@@ -997,10 +999,18 @@
 		return -ENODEV;
 	}
 
+	if (hdesc->bLength < sizeof(struct hid_descriptor)) {
+		dbg_hid("hid descriptor is too short\n");
+		return -EINVAL;
+	}
+
 	hid->version = le16_to_cpu(hdesc->bcdHID);
 	hid->country = hdesc->bCountryCode;
 
-	for (n = 0; n < hdesc->bNumDescriptors; n++)
+	num_descriptors = min_t(int, hdesc->bNumDescriptors,
+	       (hdesc->bLength - offset) / sizeof(struct hid_class_descriptor));
+
+	for (n = 0; n < num_descriptors; n++)
 		if (hdesc->desc[n].bDescriptorType == HID_DT_REPORT)
 			rsize = le16_to_cpu(hdesc->desc[n].wDescriptorLength);
 
```
