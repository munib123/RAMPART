# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 3310_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3310_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 19-60 of the vulnerable file.


static struct usb_cypress_controller cypress[] = {
	{ .id = DEVICE_SPECIFIC, .name = "Device specific", .cpu_cs_register = 0 },
	{ .id = CYPRESS_AN2135,  .name = "Cypress AN2135",  .cpu_cs_register = 0x7f92 },
	{ .id = CYPRESS_AN2235,  .name = "Cypress AN2235",  .cpu_cs_register = 0x7f92 },
	{ .id = CYPRESS_FX2,     .name = "Cypress FX2",     .cpu_cs_register = 0xe600 },
};

/*
 * load a firmware packet to the device
 */
static int usb_cypress_writemem(struct usb_device *udev,u16 addr,u8 *data, u8 len)
{
	return usb_control_msg(udev, usb_sndctrlpipe(udev,0),
			0xa0, USB_TYPE_VENDOR, addr, 0x00, data, len, 5000);
}

int usb_cypress_load_firmware(struct usb_device *udev, const struct firmware *fw, int type)
{
	struct hexline *hx;
	u8 reset;
	int ret,pos=0;

	hx = kmalloc(sizeof(*hx), GFP_KERNEL);
	if (!hx)
		return -ENOMEM;

	/* stop the CPU */
	reset = 1;
	if ((ret = usb_cypress_writemem(udev,cypress[type].cpu_cs_register,&reset,1)) != 1)
		err("could not stop the USB controller CPU.");

	while ((ret = dvb_usb_get_hexline(fw, hx, &pos)) > 0) {
		deb_fw("writing to address 0x%04x (buffer: 0x%02x %02x)\n", hx->addr, hx->len, hx->chk);
		ret = usb_cypress_writemem(udev, hx->addr, hx->data, hx->len);

		if (ret != hx->len) {
			err("error while transferring firmware (transferred size: %d, block size: %d)",
				ret, hx->len);
			ret = -EINVAL;
			break;
		}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -36,16 +36,18 @@
 int usb_cypress_load_firmware(struct usb_device *udev, const struct firmware *fw, int type)
 {
 	struct hexline *hx;
-	u8 reset;
-	int ret,pos=0;
+	u8 *buf;
+	int ret, pos = 0;
+	u16 cpu_cs_register = cypress[type].cpu_cs_register;
 
-	hx = kmalloc(sizeof(*hx), GFP_KERNEL);
-	if (!hx)
+	buf = kmalloc(sizeof(*hx), GFP_KERNEL);
+	if (!buf)
 		return -ENOMEM;
+	hx = (struct hexline *)buf;
 
 	/* stop the CPU */
-	reset = 1;
-	if ((ret = usb_cypress_writemem(udev,cypress[type].cpu_cs_register,&reset,1)) != 1)
+	buf[0] = 1;
+	if (usb_cypress_writemem(udev, cpu_cs_register, buf, 1) != 1)
 		err("could not stop the USB controller CPU.");
 
 	while ((ret = dvb_usb_get_hexline(fw, hx, &pos)) > 0) {
@@ -61,21 +63,21 @@
 	}
 	if (ret < 0) {
 		err("firmware download failed at %d with %d",pos,ret);
-		kfree(hx);
+		kfree(buf);
 		return ret;
 	}
 
 	if (ret == 0) {
 		/* restart the CPU */
-		reset = 0;
-		if (ret || usb_cypress_writemem(udev,cypress[type].cpu_cs_register,&reset,1) != 1) {
+		buf[0] = 0;
+		if (usb_cypress_writemem(udev, cpu_cs_register, buf, 1) != 1) {
 			err("could not restart the USB controller CPU.");
 			ret = -EINVAL;
 		}
 	} else
 		ret = -EIO;
 
-	kfree(hx);
+	kfree(buf);
 
 	return ret;
 }
```
