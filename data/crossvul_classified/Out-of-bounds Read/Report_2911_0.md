# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2911_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2911_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1-32 of the vulnerable file.

#include <linux/usb.h>
#include <linux/usb/hcd.h>
#include "usb.h"

static int uas_is_interface(struct usb_host_interface *intf)
{
	return (intf->desc.bInterfaceClass == USB_CLASS_MASS_STORAGE &&
		intf->desc.bInterfaceSubClass == USB_SC_SCSI &&
		intf->desc.bInterfaceProtocol == USB_PR_UAS);
}

static int uas_find_uas_alt_setting(struct usb_interface *intf)
{
	int i;

	for (i = 0; i < intf->num_altsetting; i++) {
		struct usb_host_interface *alt = &intf->altsetting[i];

		if (uas_is_interface(alt))
			return alt->desc.bAlternateSetting;
	}

	return -ENODEV;
}

static int uas_find_endpoints(struct usb_host_interface *alt,
			      struct usb_host_endpoint *eps[])
{
	struct usb_host_endpoint *endpoint = alt->endpoint;
	unsigned i, n_endpoints = alt->desc.bNumEndpoints;

	for (i = 0; i < n_endpoints; i++) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -9,7 +9,8 @@
 		intf->desc.bInterfaceProtocol == USB_PR_UAS);
 }
 
-static int uas_find_uas_alt_setting(struct usb_interface *intf)
+static struct usb_host_interface *uas_find_uas_alt_setting(
+		struct usb_interface *intf)
 {
 	int i;
 
@@ -17,10 +18,10 @@
 		struct usb_host_interface *alt = &intf->altsetting[i];
 
 		if (uas_is_interface(alt))
-			return alt->desc.bAlternateSetting;
+			return alt;
 	}
 
-	return -ENODEV;
+	return NULL;
 }
 
 static int uas_find_endpoints(struct usb_host_interface *alt,
@@ -58,14 +59,14 @@
 	struct usb_device *udev = interface_to_usbdev(intf);
 	struct usb_hcd *hcd = bus_to_hcd(udev->bus);
 	unsigned long flags = id->driver_info;
-	int r, alt;
-
+	struct usb_host_interface *alt;
+	int r;
 
 	alt = uas_find_uas_alt_setting(intf);
-	if (alt < 0)
+	if (!alt)
 		return 0;
 
-	r = uas_find_endpoints(&intf->altsetting[alt], eps);
+	r = uas_find_endpoints(alt, eps);
 	if (r < 0)
 		return 0;
 
```
