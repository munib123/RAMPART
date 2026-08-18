# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 485_2
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `485_2`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 623-663 of the vulnerable file.

{
	int result;
	struct wusbhc *wusbhc = &hwahc->wusbhc;
	struct usb_device *usb_dev = hwahc->wa.usb_dev;
	struct device *dev = &usb_dev->dev;
	struct usb_security_descriptor *secd;
	struct usb_encryption_descriptor *etd;
	void *itr, *top;
	size_t itr_size, needed, bytes;
	u8 index;
	char buf[64];

	/* Find the host's security descriptors in the config descr bundle */
	index = (usb_dev->actconfig - usb_dev->config) /
		sizeof(usb_dev->config[0]);
	itr = usb_dev->rawdescriptors[index];
	itr_size = le16_to_cpu(usb_dev->actconfig->desc.wTotalLength);
	top = itr + itr_size;
	result = __usb_get_extra_descriptor(usb_dev->rawdescriptors[index],
			le16_to_cpu(usb_dev->actconfig->desc.wTotalLength),
			USB_DT_SECURITY, (void **) &secd);
	if (result == -1) {
		dev_warn(dev, "BUG? WUSB host has no security descriptors\n");
		return 0;
	}
	needed = sizeof(*secd);
	if (top - (void *)secd < needed) {
		dev_err(dev, "BUG? Not enough data to process security "
			"descriptor header (%zu bytes left vs %zu needed)\n",
			top - (void *) secd, needed);
		return 0;
	}
	needed = le16_to_cpu(secd->wTotalLength);
	if (top - (void *)secd < needed) {
		dev_err(dev, "BUG? Not enough data to process security "
			"descriptors (%zu bytes left vs %zu needed)\n",
			top - (void *) secd, needed);
		return 0;
	}
	/* Walk over the sec descriptors and store CCM1's on wusbhc */
	itr = (void *) secd + sizeof(*secd);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -640,7 +640,7 @@
 	top = itr + itr_size;
 	result = __usb_get_extra_descriptor(usb_dev->rawdescriptors[index],
 			le16_to_cpu(usb_dev->actconfig->desc.wTotalLength),
-			USB_DT_SECURITY, (void **) &secd);
+			USB_DT_SECURITY, (void **) &secd, sizeof(*secd));
 	if (result == -1) {
 		dev_warn(dev, "BUG? WUSB host has no security descriptors\n");
 		return 0;
```
