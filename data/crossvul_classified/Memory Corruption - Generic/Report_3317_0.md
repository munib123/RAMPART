# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 3317_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3317_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 109-149 of the vulnerable file.

MODULE_PARM_DESC(msg_level, "Override default message level");

MODULE_DEVICE_TABLE(usb, pegasus_ids);
static const struct net_device_ops pegasus_netdev_ops;

/*****/

static void async_ctrl_callback(struct urb *urb)
{
	struct usb_ctrlrequest *req = (struct usb_ctrlrequest *)urb->context;
	int status = urb->status;

	if (status < 0)
		dev_dbg(&urb->dev->dev, "%s failed with %d", __func__, status);
	kfree(req);
	usb_free_urb(urb);
}

static int get_registers(pegasus_t *pegasus, __u16 indx, __u16 size, void *data)
{
	int ret;

	ret = usb_control_msg(pegasus->usb, usb_rcvctrlpipe(pegasus->usb, 0),
			      PEGASUS_REQ_GET_REGS, PEGASUS_REQT_READ, 0,
			      indx, data, size, 1000);
	if (ret < 0)
		netif_dbg(pegasus, drv, pegasus->net,
			  "%s returned %d\n", __func__, ret);
	return ret;
}

static int set_registers(pegasus_t *pegasus, __u16 indx, __u16 size, void *data)
{
	int ret;

	ret = usb_control_msg(pegasus->usb, usb_sndctrlpipe(pegasus->usb, 0),
			      PEGASUS_REQ_SET_REGS, PEGASUS_REQT_WRITE, 0,
			      indx, data, size, 100);
	if (ret < 0)
		netif_dbg(pegasus, drv, pegasus->net,
			  "%s returned %d\n", __func__, ret);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -126,40 +126,61 @@
 
 static int get_registers(pegasus_t *pegasus, __u16 indx, __u16 size, void *data)
 {
+	u8 *buf;
 	int ret;
+
+	buf = kmalloc(size, GFP_NOIO);
+	if (!buf)
+		return -ENOMEM;
 
 	ret = usb_control_msg(pegasus->usb, usb_rcvctrlpipe(pegasus->usb, 0),
 			      PEGASUS_REQ_GET_REGS, PEGASUS_REQT_READ, 0,
-			      indx, data, size, 1000);
+			      indx, buf, size, 1000);
 	if (ret < 0)
 		netif_dbg(pegasus, drv, pegasus->net,
 			  "%s returned %d\n", __func__, ret);
+	else if (ret <= size)
+		memcpy(data, buf, ret);
+	kfree(buf);
 	return ret;
 }
 
-static int set_registers(pegasus_t *pegasus, __u16 indx, __u16 size, void *data)
-{
+static int set_registers(pegasus_t *pegasus, __u16 indx, __u16 size,
+			 const void *data)
+{
+	u8 *buf;
 	int ret;
+
+	buf = kmemdup(data, size, GFP_NOIO);
+	if (!buf)
+		return -ENOMEM;
 
 	ret = usb_control_msg(pegasus->usb, usb_sndctrlpipe(pegasus->usb, 0),
 			      PEGASUS_REQ_SET_REGS, PEGASUS_REQT_WRITE, 0,
-			      indx, data, size, 100);
+			      indx, buf, size, 100);
 	if (ret < 0)
 		netif_dbg(pegasus, drv, pegasus->net,
 			  "%s returned %d\n", __func__, ret);
+	kfree(buf);
 	return ret;
 }
 
 static int set_register(pegasus_t *pegasus, __u16 indx, __u8 data)
 {
+	u8 *buf;
 	int ret;
+
+	buf = kmemdup(&data, 1, GFP_NOIO);
+	if (!buf)
+		return -ENOMEM;
 
 	ret = usb_control_msg(pegasus->usb, usb_sndctrlpipe(pegasus->usb, 0),
 			      PEGASUS_REQ_SET_REG, PEGASUS_REQT_WRITE, data,
-			      indx, &data, 1, 1000);
+			      indx, buf, 1, 1000);
 	if (ret < 0)
 		netif_dbg(pegasus, drv, pegasus->net,
 			  "%s returned %d\n", __func__, ret);
+	kfree(buf);
 	return ret;
 }
 
```
