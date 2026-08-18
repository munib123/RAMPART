# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 3960_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3960_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 1425-1465 of the vulnerable file.

		break;
	}

	sd->sof_read = 0;

	return 0;
}

static int cit_get_packet_size(struct gspca_dev *gspca_dev)
{
	struct usb_host_interface *alt;
	struct usb_interface *intf;

	intf = usb_ifnum_to_if(gspca_dev->dev, gspca_dev->iface);
	alt = usb_altnum_to_altsetting(intf, gspca_dev->alt);
	if (!alt) {
		pr_err("Couldn't get altsetting\n");
		return -EIO;
	}

	return le16_to_cpu(alt->endpoint[0].desc.wMaxPacketSize);
}

/* Calculate the clockdiv giving us max fps given the available bandwidth */
static int cit_get_clock_div(struct gspca_dev *gspca_dev)
{
	int clock_div = 7; /* 0=30 1=25 2=20 3=15 4=12 5=7.5 6=6 7=3fps ?? */
	int fps[8] = { 30, 25, 20, 15, 12, 8, 6, 3 };
	int packet_size;

	packet_size = cit_get_packet_size(gspca_dev);
	if (packet_size < 0)
		return packet_size;

	while (clock_div > 3 &&
			1000 * packet_size >
			gspca_dev->pixfmt.width * gspca_dev->pixfmt.height *
			fps[clock_div - 1] * 3 / 2)
		clock_div--;

	gspca_dbg(gspca_dev, D_PROBE,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1442,6 +1442,9 @@
 		return -EIO;
 	}
 
+	if (alt->desc.bNumEndpoints < 1)
+		return -ENODEV;
+
 	return le16_to_cpu(alt->endpoint[0].desc.wMaxPacketSize);
 }
 
@@ -2626,6 +2629,7 @@
 
 static int sd_isoc_init(struct gspca_dev *gspca_dev)
 {
+	struct usb_interface_cache *intfc;
 	struct usb_host_interface *alt;
 	int max_packet_size;
 
@@ -2641,8 +2645,17 @@
 		break;
 	}
 
+	intfc = gspca_dev->dev->actconfig->intf_cache[0];
+
+	if (intfc->num_altsetting < 2)
+		return -ENODEV;
+
+	alt = &intfc->altsetting[1];
+
+	if (alt->desc.bNumEndpoints < 1)
+		return -ENODEV;
+
 	/* Start isoc bandwidth "negotiation" at max isoc bandwidth */
-	alt = &gspca_dev->dev->actconfig->intf_cache[0]->altsetting[1];
 	alt->endpoint[0].desc.wMaxPacketSize = cpu_to_le16(max_packet_size);
 
 	return 0;
@@ -2665,6 +2678,9 @@
 		break;
 	}
 
+	/*
+	 * Existence of altsetting and endpoint was verified in sd_isoc_init()
+	 */
 	alt = &gspca_dev->dev->actconfig->intf_cache[0]->altsetting[1];
 	packet_size = le16_to_cpu(alt->endpoint[0].desc.wMaxPacketSize);
 	if (packet_size <= min_packet_size)
```
