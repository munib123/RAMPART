# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 2835_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2835_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 869-926 of the vulnerable file.

	}

	dev->read_buffer = kmalloc (read_buffer_size, GFP_KERNEL);
	if (!dev->read_buffer)
		goto error;
	dev->interrupt_in_buffer = kmalloc (usb_endpoint_maxp(dev->interrupt_in_endpoint), GFP_KERNEL);
	if (!dev->interrupt_in_buffer)
		goto error;
	dev->interrupt_in_urb = usb_alloc_urb(0, GFP_KERNEL);
	if (!dev->interrupt_in_urb)
		goto error;
	dev->interrupt_out_buffer = kmalloc (write_buffer_size, GFP_KERNEL);
	if (!dev->interrupt_out_buffer)
		goto error;
	dev->interrupt_out_urb = usb_alloc_urb(0, GFP_KERNEL);
	if (!dev->interrupt_out_urb)
		goto error;
	dev->interrupt_in_interval = interrupt_in_interval ? interrupt_in_interval : dev->interrupt_in_endpoint->bInterval;
	dev->interrupt_out_interval = interrupt_out_interval ? interrupt_out_interval : dev->interrupt_out_endpoint->bInterval;

	/* we can register the device now, as it is ready */
	usb_set_intfdata (interface, dev);

	retval = usb_register_dev (interface, &tower_class);

	if (retval) {
		/* something prevented us from registering this driver */
		dev_err(idev, "Not able to get a minor for this device.\n");
		usb_set_intfdata (interface, NULL);
		goto error;
	}
	dev->minor = interface->minor;

	/* let the user know what node this device is now attached to */
	dev_info(&interface->dev, "LEGO USB Tower #%d now attached to major "
		 "%d minor %d\n", (dev->minor - LEGO_USB_TOWER_MINOR_BASE),
		 USB_MAJOR, dev->minor);

	/* get the firmware version and log it */
	result = usb_control_msg (udev,
				  usb_rcvctrlpipe(udev, 0),
				  LEGO_USB_TOWER_REQUEST_GET_VERSION,
				  USB_TYPE_VENDOR | USB_DIR_IN | USB_RECIP_DEVICE,
				  0,
				  0,
				  &get_version_reply,
				  sizeof(get_version_reply),
				  1000);
	if (result < 0) {
		dev_err(idev, "LEGO USB Tower get version control request failed\n");
		retval = result;
		goto error;
	}
	dev_info(&interface->dev, "LEGO USB Tower firmware version is %d.%d "
		 "build %d\n", get_version_reply.major,
		 get_version_reply.minor,
		 le16_to_cpu(get_version_reply.build_no));

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -886,24 +886,6 @@
 	dev->interrupt_in_interval = interrupt_in_interval ? interrupt_in_interval : dev->interrupt_in_endpoint->bInterval;
 	dev->interrupt_out_interval = interrupt_out_interval ? interrupt_out_interval : dev->interrupt_out_endpoint->bInterval;
 
-	/* we can register the device now, as it is ready */
-	usb_set_intfdata (interface, dev);
-
-	retval = usb_register_dev (interface, &tower_class);
-
-	if (retval) {
-		/* something prevented us from registering this driver */
-		dev_err(idev, "Not able to get a minor for this device.\n");
-		usb_set_intfdata (interface, NULL);
-		goto error;
-	}
-	dev->minor = interface->minor;
-
-	/* let the user know what node this device is now attached to */
-	dev_info(&interface->dev, "LEGO USB Tower #%d now attached to major "
-		 "%d minor %d\n", (dev->minor - LEGO_USB_TOWER_MINOR_BASE),
-		 USB_MAJOR, dev->minor);
-
 	/* get the firmware version and log it */
 	result = usb_control_msg (udev,
 				  usb_rcvctrlpipe(udev, 0),
@@ -924,6 +906,23 @@
 		 get_version_reply.minor,
 		 le16_to_cpu(get_version_reply.build_no));
 
+	/* we can register the device now, as it is ready */
+	usb_set_intfdata (interface, dev);
+
+	retval = usb_register_dev (interface, &tower_class);
+
+	if (retval) {
+		/* something prevented us from registering this driver */
+		dev_err(idev, "Not able to get a minor for this device.\n");
+		usb_set_intfdata (interface, NULL);
+		goto error;
+	}
+	dev->minor = interface->minor;
+
+	/* let the user know what node this device is now attached to */
+	dev_info(&interface->dev, "LEGO USB Tower #%d now attached to major "
+		 "%d minor %d\n", (dev->minor - LEGO_USB_TOWER_MINOR_BASE),
+		 USB_MAJOR, dev->minor);
 
 exit:
 	return retval;
```
