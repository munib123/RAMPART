# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 3318_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3318_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 138-180 of the vulnerable file.

	u8 *intr_buff;
	u8 phy;
};

typedef struct rtl8150 rtl8150_t;

struct async_req {
	struct usb_ctrlrequest dr;
	u16 rx_creg;
};

static const char driver_name [] = "rtl8150";

/*
**
**	device related part of the code
**
*/
static int get_registers(rtl8150_t * dev, u16 indx, u16 size, void *data)
{
	return usb_control_msg(dev->udev, usb_rcvctrlpipe(dev->udev, 0),
			       RTL8150_REQ_GET_REGS, RTL8150_REQT_READ,
			       indx, 0, data, size, 500);
}

static int set_registers(rtl8150_t * dev, u16 indx, u16 size, void *data)
{
	return usb_control_msg(dev->udev, usb_sndctrlpipe(dev->udev, 0),
			       RTL8150_REQ_SET_REGS, RTL8150_REQT_WRITE,
			       indx, 0, data, size, 500);
}

static void async_set_reg_cb(struct urb *urb)
{
	struct async_req *req = (struct async_req *)urb->context;
	int status = urb->status;

	if (status < 0)
		dev_dbg(&urb->dev->dev, "%s failed with %d", __func__, status);
	kfree(req);
	usb_free_urb(urb);
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -155,16 +155,36 @@
 */
 static int get_registers(rtl8150_t * dev, u16 indx, u16 size, void *data)
 {
-	return usb_control_msg(dev->udev, usb_rcvctrlpipe(dev->udev, 0),
-			       RTL8150_REQ_GET_REGS, RTL8150_REQT_READ,
-			       indx, 0, data, size, 500);
-}
-
-static int set_registers(rtl8150_t * dev, u16 indx, u16 size, void *data)
-{
-	return usb_control_msg(dev->udev, usb_sndctrlpipe(dev->udev, 0),
-			       RTL8150_REQ_SET_REGS, RTL8150_REQT_WRITE,
-			       indx, 0, data, size, 500);
+	void *buf;
+	int ret;
+
+	buf = kmalloc(size, GFP_NOIO);
+	if (!buf)
+		return -ENOMEM;
+
+	ret = usb_control_msg(dev->udev, usb_rcvctrlpipe(dev->udev, 0),
+			      RTL8150_REQ_GET_REGS, RTL8150_REQT_READ,
+			      indx, 0, buf, size, 500);
+	if (ret > 0 && ret <= size)
+		memcpy(data, buf, ret);
+	kfree(buf);
+	return ret;
+}
+
+static int set_registers(rtl8150_t * dev, u16 indx, u16 size, const void *data)
+{
+	void *buf;
+	int ret;
+
+	buf = kmemdup(data, size, GFP_NOIO);
+	if (!buf)
+		return -ENOMEM;
+
+	ret = usb_control_msg(dev->udev, usb_sndctrlpipe(dev->udev, 0),
+			      RTL8150_REQ_SET_REGS, RTL8150_REQT_WRITE,
+			      indx, 0, buf, size, 500);
+	kfree(buf);
+	return ret;
 }
 
 static void async_set_reg_cb(struct urb *urb)
```
