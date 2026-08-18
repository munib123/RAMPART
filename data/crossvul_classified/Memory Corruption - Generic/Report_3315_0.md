# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 3315_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3315_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 891-934 of the vulnerable file.

		dev_err(&intf->dev, "Couldn't register candev (err=%d)\n", rc);
		return ERR_PTR(rc);
	}

	return dev;
}

static void gs_destroy_candev(struct gs_can *dev)
{
	unregister_candev(dev->netdev);
	usb_kill_anchored_urbs(&dev->tx_submitted);
	free_candev(dev->netdev);
}

static int gs_usb_probe(struct usb_interface *intf,
			const struct usb_device_id *id)
{
	struct gs_usb *dev;
	int rc = -ENOMEM;
	unsigned int icount, i;
	struct gs_host_config hconf = {
		.byte_order = 0x0000beef,
	};
	struct gs_device_config dconf;

	/* send host config */
	rc = usb_control_msg(interface_to_usbdev(intf),
			     usb_sndctrlpipe(interface_to_usbdev(intf), 0),
			     GS_USB_BREQ_HOST_FORMAT,
			     USB_DIR_OUT|USB_TYPE_VENDOR|USB_RECIP_INTERFACE,
			     1,
			     intf->altsetting[0].desc.bInterfaceNumber,
			     &hconf,
			     sizeof(hconf),
			     1000);

	if (rc < 0) {
		dev_err(&intf->dev, "Couldn't send data format (err=%d)\n",
			rc);
		return rc;
	}

	/* read device config */
	rc = usb_control_msg(interface_to_usbdev(intf),
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -908,10 +908,14 @@
 	struct gs_usb *dev;
 	int rc = -ENOMEM;
 	unsigned int icount, i;
-	struct gs_host_config hconf = {
-		.byte_order = 0x0000beef,
-	};
-	struct gs_device_config dconf;
+	struct gs_host_config *hconf;
+	struct gs_device_config *dconf;
+
+	hconf = kmalloc(sizeof(*hconf), GFP_KERNEL);
+	if (!hconf)
+		return -ENOMEM;
+
+	hconf->byte_order = 0x0000beef;
 
 	/* send host config */
 	rc = usb_control_msg(interface_to_usbdev(intf),
@@ -920,15 +924,21 @@
 			     USB_DIR_OUT|USB_TYPE_VENDOR|USB_RECIP_INTERFACE,
 			     1,
 			     intf->altsetting[0].desc.bInterfaceNumber,
-			     &hconf,
-			     sizeof(hconf),
+			     hconf,
+			     sizeof(*hconf),
 			     1000);
+
+	kfree(hconf);
 
 	if (rc < 0) {
 		dev_err(&intf->dev, "Couldn't send data format (err=%d)\n",
 			rc);
 		return rc;
 	}
+
+	dconf = kmalloc(sizeof(*dconf), GFP_KERNEL);
+	if (!dconf)
+		return -ENOMEM;
 
 	/* read device config */
 	rc = usb_control_msg(interface_to_usbdev(intf),
@@ -937,28 +947,33 @@
 			     USB_DIR_IN|USB_TYPE_VENDOR|USB_RECIP_INTERFACE,
 			     1,
 			     intf->altsetting[0].desc.bInterfaceNumber,
-			     &dconf,
-			     sizeof(dconf),
+			     dconf,
+			     sizeof(*dconf),
 			     1000);
 	if (rc < 0) {
 		dev_err(&intf->dev, "Couldn't get device config: (err=%d)\n",
 			rc);
+		kfree(dconf);
 		return rc;
 	}
 
-	icount = dconf.icount + 1;
+	icount = dconf->icount + 1;
 	dev_info(&intf->dev, "Configuring for %d interfaces\n", icount);
 
 	if (icount > GS_MAX_INTF) {
 		dev_err(&intf->dev,
 			"Driver cannot handle more that %d CAN interfaces\n",
 			GS_MAX_INTF);
+		kfree(dconf);
 		return -EINVAL;
 	}
 
 	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
-	if (!dev)
+	if (!dev) {
+		kfree(dconf);
 		return -ENOMEM;
+	}
+
 	init_usb_anchor(&dev->rx_submitted);
 
 	atomic_set(&dev->active_channels, 0);
@@ -967,7 +982,7 @@
 	dev->udev = interface_to_usbdev(intf);
 
 	for (i = 0; i < icount; i++) {
-		dev->canch[i] = gs_make_candev(i, intf, &dconf);
+		dev->canch[i] = gs_make_candev(i, intf, dconf);
 		if (IS_ERR_OR_NULL(dev->canch[i])) {
 			/* save error code to return later */
 			rc = PTR_ERR(dev->canch[i]);
@@ -978,11 +993,14 @@
 				gs_destroy_candev(dev->canch[i]);
 
 			usb_kill_anchored_urbs(&dev->rx_submitted);
+			kfree(dconf);
 			kfree(dev);
 			return rc;
 		}
 		dev->canch[i]->parent = dev;
 	}
+
+	kfree(dconf);
 
 	return 0;
 }
```
