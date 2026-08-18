# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 1215_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1215_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 959-1000 of the vulnerable file.

				 struct dvb_usb_device_description **desc,
				 int *cold)
{
	int ret;
	u8 reply, *buf;

	buf = kmalloc(FW_BULKOUT_SIZE + 2, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	ret = af9005_boot_packet(udev, FW_CONFIG, &reply,
				 buf, FW_BULKOUT_SIZE + 2);
	if (ret)
		goto err;
	deb_info("result of FW_CONFIG in identify state %d\n", reply);
	if (reply == 0x01)
		*cold = 1;
	else if (reply == 0x02)
		*cold = 0;
	else
		return -EIO;
	deb_info("Identify state cold = %d\n", *cold);

err:
	kfree(buf);
	return ret;
}

static struct dvb_usb_device_properties af9005_properties;

static int af9005_usb_probe(struct usb_interface *intf,
			    const struct usb_device_id *id)
{
	return dvb_usb_device_init(intf, &af9005_properties,
				  THIS_MODULE, NULL, adapter_nr);
}

enum af9005_usb_table_entry {
	AFATECH_AF9005,
	TERRATEC_AF9005,
	ANSONIC_AF9005,
};
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -976,8 +976,9 @@
 	else if (reply == 0x02)
 		*cold = 0;
 	else
-		return -EIO;
-	deb_info("Identify state cold = %d\n", *cold);
+		ret = -EIO;
+	if (!ret)
+		deb_info("Identify state cold = %d\n", *cold);
 
 err:
 	kfree(buf);
```
