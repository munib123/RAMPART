# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 3313_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3313_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 995-1036 of the vulnerable file.

		goto err_free_all;

	dev_info(&d->udev->dev,
			"%s: '%s' successfully initialized and connected\n",
			KBUILD_MODNAME, d->name);
exit:
	usb_set_intfdata(intf, d);

	return 0;
err_free_all:
	dvb_usbv2_exit(d);
err:
	dev_dbg(&udev->dev, "%s: failed=%d\n", __func__, ret);
	return ret;
}
EXPORT_SYMBOL(dvb_usbv2_probe);

void dvb_usbv2_disconnect(struct usb_interface *intf)
{
	struct dvb_usb_device *d = usb_get_intfdata(intf);
	const char *name = d->name;
	struct device dev = d->udev->dev;

	dev_dbg(&d->udev->dev, "%s: bInterfaceNumber=%d\n", __func__,
			intf->cur_altsetting->desc.bInterfaceNumber);

	if (d->props->exit)
		d->props->exit(d);

	dvb_usbv2_exit(d);

	dev_info(&dev, "%s: '%s' successfully deinitialized and disconnected\n",
			KBUILD_MODNAME, name);
}
EXPORT_SYMBOL(dvb_usbv2_disconnect);

int dvb_usbv2_suspend(struct usb_interface *intf, pm_message_t msg)
{
	struct dvb_usb_device *d = usb_get_intfdata(intf);
	int ret = 0, i, active_fe;
	struct dvb_frontend *fe;
	dev_dbg(&d->udev->dev, "%s:\n", __func__);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1012,8 +1012,8 @@
 void dvb_usbv2_disconnect(struct usb_interface *intf)
 {
 	struct dvb_usb_device *d = usb_get_intfdata(intf);
-	const char *name = d->name;
-	struct device dev = d->udev->dev;
+	const char *devname = kstrdup(dev_name(&d->udev->dev), GFP_KERNEL);
+	const char *drvname = d->name;
 
 	dev_dbg(&d->udev->dev, "%s: bInterfaceNumber=%d\n", __func__,
 			intf->cur_altsetting->desc.bInterfaceNumber);
@@ -1023,8 +1023,9 @@
 
 	dvb_usbv2_exit(d);
 
-	dev_info(&dev, "%s: '%s' successfully deinitialized and disconnected\n",
-			KBUILD_MODNAME, name);
+	pr_info("%s: '%s:%s' successfully deinitialized and disconnected\n",
+		KBUILD_MODNAME, drvname, devname);
+	kfree(devname);
 }
 EXPORT_SYMBOL(dvb_usbv2_disconnect);
 
```
