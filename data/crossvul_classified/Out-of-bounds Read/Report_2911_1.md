# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2911_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2911_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 856-896 of the vulnerable file.


#define UNUSUAL_DEV(id_vendor, id_product, bcdDeviceMin, bcdDeviceMax, \
		    vendorName, productName, useProtocol, useTransport, \
		    initFunction, flags) \
{ USB_DEVICE_VER(id_vendor, id_product, bcdDeviceMin, bcdDeviceMax), \
	.driver_info = (flags) }

static struct usb_device_id uas_usb_ids[] = {
#	include "unusual_uas.h"
	{ USB_INTERFACE_INFO(USB_CLASS_MASS_STORAGE, USB_SC_SCSI, USB_PR_BULK) },
	{ USB_INTERFACE_INFO(USB_CLASS_MASS_STORAGE, USB_SC_SCSI, USB_PR_UAS) },
	{ }
};
MODULE_DEVICE_TABLE(usb, uas_usb_ids);

#undef UNUSUAL_DEV

static int uas_switch_interface(struct usb_device *udev,
				struct usb_interface *intf)
{
	int alt;

	alt = uas_find_uas_alt_setting(intf);
	if (alt < 0)
		return alt;

	return usb_set_interface(udev,
			intf->altsetting[0].desc.bInterfaceNumber, alt);
}

static int uas_configure_endpoints(struct uas_dev_info *devinfo)
{
	struct usb_host_endpoint *eps[4] = { };
	struct usb_device *udev = devinfo->udev;
	int r;

	r = uas_find_endpoints(devinfo->intf->cur_altsetting, eps);
	if (r)
		return r;

	devinfo->cmd_pipe = usb_sndbulkpipe(udev,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -873,14 +873,14 @@
 static int uas_switch_interface(struct usb_device *udev,
 				struct usb_interface *intf)
 {
-	int alt;
+	struct usb_host_interface *alt;
 
 	alt = uas_find_uas_alt_setting(intf);
-	if (alt < 0)
-		return alt;
-
-	return usb_set_interface(udev,
-			intf->altsetting[0].desc.bInterfaceNumber, alt);
+	if (!alt)
+		return -ENODEV;
+
+	return usb_set_interface(udev, alt->desc.bInterfaceNumber,
+			alt->desc.bAlternateSetting);
 }
 
 static int uas_configure_endpoints(struct uas_dev_info *devinfo)
```
