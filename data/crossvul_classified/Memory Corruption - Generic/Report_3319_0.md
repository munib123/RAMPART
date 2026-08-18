# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 3319_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3319_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 759-799 of the vulnerable file.

	.ndo_stop		= catc_stop,
	.ndo_start_xmit		= catc_start_xmit,

	.ndo_tx_timeout		= catc_tx_timeout,
	.ndo_set_rx_mode	= catc_set_multicast_list,
	.ndo_set_mac_address 	= eth_mac_addr,
	.ndo_validate_addr	= eth_validate_addr,
};

/*
 * USB probe, disconnect.
 */

static int catc_probe(struct usb_interface *intf, const struct usb_device_id *id)
{
	struct device *dev = &intf->dev;
	struct usb_device *usbdev = interface_to_usbdev(intf);
	struct net_device *netdev;
	struct catc *catc;
	u8 broadcast[ETH_ALEN];
	int i, pktsz, ret;

	if (usb_set_interface(usbdev,
			intf->altsetting->desc.bInterfaceNumber, 1)) {
		dev_err(dev, "Can't set altsetting 1.\n");
		return -EIO;
	}

	netdev = alloc_etherdev(sizeof(struct catc));
	if (!netdev)
		return -ENOMEM;

	catc = netdev_priv(netdev);

	netdev->netdev_ops = &catc_netdev_ops;
	netdev->watchdog_timeo = TX_TIMEOUT;
	netdev->ethtool_ops = &ops;

	catc->usbdev = usbdev;
	catc->netdev = netdev;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -776,7 +776,7 @@
 	struct net_device *netdev;
 	struct catc *catc;
 	u8 broadcast[ETH_ALEN];
-	int i, pktsz, ret;
+	int pktsz, ret;
 
 	if (usb_set_interface(usbdev,
 			intf->altsetting->desc.bInterfaceNumber, 1)) {
@@ -840,15 +840,24 @@
                 catc->irq_buf, 2, catc_irq_done, catc, 1);
 
 	if (!catc->is_f5u011) {
+		u32 *buf;
+		int i;
+
 		dev_dbg(dev, "Checking memory size\n");
 
-		i = 0x12345678;
-		catc_write_mem(catc, 0x7a80, &i, 4);
-		i = 0x87654321;	
-		catc_write_mem(catc, 0xfa80, &i, 4);
-		catc_read_mem(catc, 0x7a80, &i, 4);
+		buf = kmalloc(4, GFP_KERNEL);
+		if (!buf) {
+			ret = -ENOMEM;
+			goto fail_free;
+		}
+
+		*buf = 0x12345678;
+		catc_write_mem(catc, 0x7a80, buf, 4);
+		*buf = 0x87654321;
+		catc_write_mem(catc, 0xfa80, buf, 4);
+		catc_read_mem(catc, 0x7a80, buf, 4);
 	  
-		switch (i) {
+		switch (*buf) {
 		case 0x12345678:
 			catc_set_reg(catc, TxBufCount, 8);
 			catc_set_reg(catc, RxBufCount, 32);
@@ -863,6 +872,8 @@
 			dev_dbg(dev, "32k Memory\n");
 			break;
 		}
+
+		kfree(buf);
 	  
 		dev_dbg(dev, "Getting MAC from SEEROM.\n");
 	  
```
