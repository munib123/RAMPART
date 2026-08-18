# CrossVul Fix Pair: Insertion of Sensitive Information into Log File in c
**Pair ID:** 3117_0
**Vulnerability Class:** Insertion of Sensitive Information into Log File
**CWE:** CWE-532
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3117_0`)

## Vulnerability Information & PoC

## Description
Insertion of Sensitive Information into Log File - While logging all information may be helpful during development stages, it is important that logging levels be set appropriately before a product ships so that sensitive user data and system inform...

## Vulnerable Code
```c
Lines 175-218 of the vulnerable file.

	u8 *status_buf;
	__u16 status;

	dev_info(&port->serial->dev->dev, "sending SIO Poll request\n");

	status_buf = kmalloc(KLSI_STATUSBUF_LEN, GFP_KERNEL);
	if (!status_buf)
		return -ENOMEM;

	status_buf[0] = 0xff;
	status_buf[1] = 0xff;
	rc = usb_control_msg(port->serial->dev,
			     usb_rcvctrlpipe(port->serial->dev, 0),
			     KL5KUSB105A_SIO_POLL,
			     USB_TYPE_VENDOR | USB_DIR_IN,
			     0, /* value */
			     0, /* index */
			     status_buf, KLSI_STATUSBUF_LEN,
			     10000
			     );
	if (rc < 0)
		dev_err(&port->dev, "Reading line status failed (error = %d)\n",
			rc);
	else {
		status = get_unaligned_le16(status_buf);

		dev_info(&port->serial->dev->dev, "read status %x %x\n",
			 status_buf[0], status_buf[1]);

		*line_state_p = klsi_105_status2linestate(status);
	}

	kfree(status_buf);
	return rc;
}


/*
 * Driver's tty interface functions
 */

static int klsi_105_port_probe(struct usb_serial_port *port)
{
	struct klsi_105_private *priv;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -192,10 +192,11 @@
 			     status_buf, KLSI_STATUSBUF_LEN,
 			     10000
 			     );
-	if (rc < 0)
-		dev_err(&port->dev, "Reading line status failed (error = %d)\n",
-			rc);
-	else {
+	if (rc != KLSI_STATUSBUF_LEN) {
+		dev_err(&port->dev, "reading line status failed: %d\n", rc);
+		if (rc >= 0)
+			rc = -EIO;
+	} else {
 		status = get_unaligned_le16(status_buf);
 
 		dev_info(&port->serial->dev->dev, "read status %x %x\n",
```
