# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 3116_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3116_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 100-140 of the vulnerable file.

	dev_dbg(&usb_dev->dev, "atusb_command: cmd = 0x%x\n", cmd);
	return atusb_control_msg(atusb, usb_sndctrlpipe(usb_dev, 0),
				 cmd, ATUSB_REQ_TO_DEV, arg, 0, NULL, 0, 1000);
}

static int atusb_write_reg(struct atusb *atusb, uint8_t reg, uint8_t value)
{
	struct usb_device *usb_dev = atusb->usb_dev;

	dev_dbg(&usb_dev->dev, "atusb_write_reg: 0x%02x <- 0x%02x\n",
		reg, value);
	return atusb_control_msg(atusb, usb_sndctrlpipe(usb_dev, 0),
				 ATUSB_REG_WRITE, ATUSB_REQ_TO_DEV,
				 value, reg, NULL, 0, 1000);
}

static int atusb_read_reg(struct atusb *atusb, uint8_t reg)
{
	struct usb_device *usb_dev = atusb->usb_dev;
	int ret;
	uint8_t value;

	dev_dbg(&usb_dev->dev, "atusb: reg = 0x%x\n", reg);
	ret = atusb_control_msg(atusb, usb_rcvctrlpipe(usb_dev, 0),
				ATUSB_REG_READ, ATUSB_REQ_FROM_DEV,
				0, reg, &value, 1, 1000);
	return ret >= 0 ? value : ret;
}

static int atusb_write_subreg(struct atusb *atusb, uint8_t reg, uint8_t mask,
			      uint8_t shift, uint8_t value)
{
	struct usb_device *usb_dev = atusb->usb_dev;
	uint8_t orig, tmp;
	int ret = 0;

	dev_dbg(&usb_dev->dev, "atusb_write_subreg: 0x%02x <- 0x%02x\n",
		reg, value);

	orig = atusb_read_reg(atusb, reg);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -117,13 +117,26 @@
 {
 	struct usb_device *usb_dev = atusb->usb_dev;
 	int ret;
+	uint8_t *buffer;
 	uint8_t value;
+
+	buffer = kmalloc(1, GFP_KERNEL);
+	if (!buffer)
+		return -ENOMEM;
 
 	dev_dbg(&usb_dev->dev, "atusb: reg = 0x%x\n", reg);
 	ret = atusb_control_msg(atusb, usb_rcvctrlpipe(usb_dev, 0),
 				ATUSB_REG_READ, ATUSB_REQ_FROM_DEV,
-				0, reg, &value, 1, 1000);
-	return ret >= 0 ? value : ret;
+				0, reg, buffer, 1, 1000);
+
+	if (ret >= 0) {
+		value = buffer[0];
+		kfree(buffer);
+		return value;
+	} else {
+		kfree(buffer);
+		return ret;
+	}
 }
 
 static int atusb_write_subreg(struct atusb *atusb, uint8_t reg, uint8_t mask,
@@ -608,8 +621,12 @@
 static int atusb_get_and_show_revision(struct atusb *atusb)
 {
 	struct usb_device *usb_dev = atusb->usb_dev;
-	unsigned char buffer[3];
-	int ret;
+	unsigned char *buffer;
+	int ret;
+
+	buffer = kmalloc(3, GFP_KERNEL);
+	if (!buffer)
+		return -ENOMEM;
 
 	/* Get a couple of the ATMega Firmware values */
 	ret = atusb_control_msg(atusb, usb_rcvctrlpipe(usb_dev, 0),
@@ -631,14 +648,19 @@
 		dev_info(&usb_dev->dev, "Please update to version 0.2 or newer");
 	}
 
+	kfree(buffer);
 	return ret;
 }
 
 static int atusb_get_and_show_build(struct atusb *atusb)
 {
 	struct usb_device *usb_dev = atusb->usb_dev;
-	char build[ATUSB_BUILD_SIZE + 1];
-	int ret;
+	char *build;
+	int ret;
+
+	build = kmalloc(ATUSB_BUILD_SIZE + 1, GFP_KERNEL);
+	if (!build)
+		return -ENOMEM;
 
 	ret = atusb_control_msg(atusb, usb_rcvctrlpipe(usb_dev, 0),
 				ATUSB_BUILD, ATUSB_REQ_FROM_DEV, 0, 0,
@@ -648,6 +670,7 @@
 		dev_info(&usb_dev->dev, "Firmware: build %s\n", build);
 	}
 
+	kfree(build);
 	return ret;
 }
 
```
