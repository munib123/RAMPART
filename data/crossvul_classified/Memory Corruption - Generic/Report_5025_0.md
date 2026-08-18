# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5025_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5025_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 724-764 of the vulnerable file.

	int size;

	if (ud->side == USBIP_STUB) {
		/* the direction of urb must be OUT. */
		if (usb_pipein(urb->pipe))
			return 0;

		size = urb->transfer_buffer_length;
	} else {
		/* the direction of urb must be IN. */
		if (usb_pipeout(urb->pipe))
			return 0;

		size = urb->actual_length;
	}

	/* no need to recv xbuff */
	if (!(size > 0))
		return 0;

	ret = usbip_recv(ud->tcp_socket, urb->transfer_buffer, size);
	if (ret != size) {
		dev_err(&urb->dev->dev, "recv xbuf, %d\n", ret);
		if (ud->side == USBIP_STUB) {
			usbip_event_add(ud, SDEV_EVENT_ERROR_TCP);
		} else {
			usbip_event_add(ud, VDEV_EVENT_ERROR_TCP);
			return -EPIPE;
		}
	}

	return ret;
}
EXPORT_SYMBOL_GPL(usbip_recv_xbuff);

static int __init usbip_core_init(void)
{
	pr_info(DRIVER_DESC " v" USBIP_VERSION "\n");
	return 0;
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -741,6 +741,17 @@
 	if (!(size > 0))
 		return 0;
 
+	if (size > urb->transfer_buffer_length) {
+		/* should not happen, probably malicious packet */
+		if (ud->side == USBIP_STUB) {
+			usbip_event_add(ud, SDEV_EVENT_ERROR_TCP);
+			return 0;
+		} else {
+			usbip_event_add(ud, VDEV_EVENT_ERROR_TCP);
+			return -EPIPE;
+		}
+	}
+
 	ret = usbip_recv(ud->tcp_socket, urb->transfer_buffer, size);
 	if (ret != size) {
 		dev_err(&urb->dev->dev, "recv xbuf, %d\n", ret);
```
