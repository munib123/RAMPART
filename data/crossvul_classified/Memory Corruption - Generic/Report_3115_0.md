# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 3115_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3115_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 131-171 of the vulnerable file.

#define K90_MACRO_MODE_HW 0x0001

#define K90_MACRO_LED_ON  0x0020
#define K90_MACRO_LED_OFF 0x0040

/*
 * LED class devices
 */

#define K90_BACKLIGHT_LED_SUFFIX "::backlight"
#define K90_RECORD_LED_SUFFIX "::record"

static enum led_brightness k90_backlight_get(struct led_classdev *led_cdev)
{
	int ret;
	struct k90_led *led = container_of(led_cdev, struct k90_led, cdev);
	struct device *dev = led->cdev.dev->parent;
	struct usb_interface *usbif = to_usb_interface(dev->parent);
	struct usb_device *usbdev = interface_to_usbdev(usbif);
	int brightness;
	char data[8];

	ret = usb_control_msg(usbdev, usb_rcvctrlpipe(usbdev, 0),
			      K90_REQUEST_STATUS,
			      USB_DIR_IN | USB_TYPE_VENDOR |
			      USB_RECIP_DEVICE, 0, 0, data, 8,
			      USB_CTRL_SET_TIMEOUT);
	if (ret < 0) {
		dev_warn(dev, "Failed to get K90 initial state (error %d).\n",
			 ret);
		return -EIO;
	}
	brightness = data[4];
	if (brightness < 0 || brightness > 3) {
		dev_warn(dev,
			 "Read invalid backlight brightness: %02hhx.\n",
			 data[4]);
		return -EIO;
	}
	return brightness;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -148,7 +148,11 @@
 	struct usb_interface *usbif = to_usb_interface(dev->parent);
 	struct usb_device *usbdev = interface_to_usbdev(usbif);
 	int brightness;
-	char data[8];
+	char *data;
+
+	data = kmalloc(8, GFP_KERNEL);
+	if (!data)
+		return -ENOMEM;
 
 	ret = usb_control_msg(usbdev, usb_rcvctrlpipe(usbdev, 0),
 			      K90_REQUEST_STATUS,
@@ -158,16 +162,22 @@
 	if (ret < 0) {
 		dev_warn(dev, "Failed to get K90 initial state (error %d).\n",
 			 ret);
-		return -EIO;
+		ret = -EIO;
+		goto out;
 	}
 	brightness = data[4];
 	if (brightness < 0 || brightness > 3) {
 		dev_warn(dev,
 			 "Read invalid backlight brightness: %02hhx.\n",
 			 data[4]);
-		return -EIO;
-	}
-	return brightness;
+		ret = -EIO;
+		goto out;
+	}
+	ret = brightness;
+out:
+	kfree(data);
+
+	return ret;
 }
 
 static enum led_brightness k90_record_led_get(struct led_classdev *led_cdev)
@@ -253,7 +263,11 @@
 	struct usb_interface *usbif = to_usb_interface(dev->parent);
 	struct usb_device *usbdev = interface_to_usbdev(usbif);
 	const char *macro_mode;
-	char data[8];
+	char *data;
+
+	data = kmalloc(2, GFP_KERNEL);
+	if (!data)
+		return -ENOMEM;
 
 	ret = usb_control_msg(usbdev, usb_rcvctrlpipe(usbdev, 0),
 			      K90_REQUEST_GET_MODE,
@@ -263,7 +277,8 @@
 	if (ret < 0) {
 		dev_warn(dev, "Failed to get K90 initial mode (error %d).\n",
 			 ret);
-		return -EIO;
+		ret = -EIO;
+		goto out;
 	}
 
 	switch (data[0]) {
@@ -277,10 +292,15 @@
 	default:
 		dev_warn(dev, "K90 in unknown mode: %02hhx.\n",
 			 data[0]);
-		return -EIO;
-	}
-
-	return snprintf(buf, PAGE_SIZE, "%s\n", macro_mode);
+		ret = -EIO;
+		goto out;
+	}
+
+	ret = snprintf(buf, PAGE_SIZE, "%s\n", macro_mode);
+out:
+	kfree(data);
+
+	return ret;
 }
 
 static ssize_t k90_store_macro_mode(struct device *dev,
@@ -320,7 +340,11 @@
 	struct usb_interface *usbif = to_usb_interface(dev->parent);
 	struct usb_device *usbdev = interface_to_usbdev(usbif);
 	int current_profile;
-	char data[8];
+	char *data;
+
+	data = kmalloc(8, GFP_KERNEL);
+	if (!data)
+		return -ENOMEM;
 
 	ret = usb_control_msg(usbdev, usb_rcvctrlpipe(usbdev, 0),
 			      K90_REQUEST_STATUS,
@@ -330,16 +354,22 @@
 	if (ret < 0) {
 		dev_warn(dev, "Failed to get K90 initial state (error %d).\n",
 			 ret);
-		return -EIO;
+		ret = -EIO;
+		goto out;
 	}
 	current_profile = data[7];
 	if (current_profile < 1 || current_profile > 3) {
 		dev_warn(dev, "Read invalid current profile: %02hhx.\n",
 			 data[7]);
-		return -EIO;
-	}
-
-	return snprintf(buf, PAGE_SIZE, "%d\n", current_profile);
+		ret = -EIO;
+		goto out;
+	}
+
+	ret = snprintf(buf, PAGE_SIZE, "%d\n", current_profile);
+out:
+	kfree(data);
+
+	return ret;
 }
 
 static ssize_t k90_store_current_profile(struct device *dev,
```
