# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 5048_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5048_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 1299-1342 of the vulnerable file.

{
	struct usbdevfs_getdriver gd;
	struct usb_interface *intf;
	int ret;

	if (copy_from_user(&gd, arg, sizeof(gd)))
		return -EFAULT;
	intf = usb_ifnum_to_if(ps->dev, gd.interface);
	if (!intf || !intf->dev.driver)
		ret = -ENODATA;
	else {
		strlcpy(gd.driver, intf->dev.driver->name,
				sizeof(gd.driver));
		ret = (copy_to_user(arg, &gd, sizeof(gd)) ? -EFAULT : 0);
	}
	return ret;
}

static int proc_connectinfo(struct usb_dev_state *ps, void __user *arg)
{
	struct usbdevfs_connectinfo ci = {
		.devnum = ps->dev->devnum,
		.slow = ps->dev->speed == USB_SPEED_LOW
	};

	if (copy_to_user(arg, &ci, sizeof(ci)))
		return -EFAULT;
	return 0;
}

static int proc_resetdevice(struct usb_dev_state *ps)
{
	struct usb_host_config *actconfig = ps->dev->actconfig;
	struct usb_interface *interface;
	int i, number;

	/* Don't allow a device reset if the process has dropped the
	 * privilege to do such things and any of the interfaces are
	 * currently claimed.
	 */
	if (ps->privileges_dropped && actconfig) {
		for (i = 0; i < actconfig->desc.bNumInterfaces; ++i) {
			interface = actconfig->interface[i];
			number = interface->cur_altsetting->desc.bInterfaceNumber;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1316,10 +1316,11 @@
 
 static int proc_connectinfo(struct usb_dev_state *ps, void __user *arg)
 {
-	struct usbdevfs_connectinfo ci = {
-		.devnum = ps->dev->devnum,
-		.slow = ps->dev->speed == USB_SPEED_LOW
-	};
+	struct usbdevfs_connectinfo ci;
+
+	memset(&ci, 0, sizeof(ci));
+	ci.devnum = ps->dev->devnum;
+	ci.slow = ps->dev->speed == USB_SPEED_LOW;
 
 	if (copy_to_user(arg, &ci, sizeof(ci)))
 		return -EFAULT;
```
