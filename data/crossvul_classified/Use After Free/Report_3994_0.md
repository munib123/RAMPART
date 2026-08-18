# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 3994_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3994_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 572-612 of the vulnerable file.

	wait_for_completion(&io->complete);

	sg_clean(io);
}
EXPORT_SYMBOL_GPL(usb_sg_wait);

/**
 * usb_sg_cancel - stop scatter/gather i/o issued by usb_sg_wait()
 * @io: request block, initialized with usb_sg_init()
 *
 * This stops a request after it has been started by usb_sg_wait().
 * It can also prevents one initialized by usb_sg_init() from starting,
 * so that call just frees resources allocated to the request.
 */
void usb_sg_cancel(struct usb_sg_request *io)
{
	unsigned long flags;
	int i, retval;

	spin_lock_irqsave(&io->lock, flags);
	if (io->status) {
		spin_unlock_irqrestore(&io->lock, flags);
		return;
	}
	/* shut everything down */
	io->status = -ECONNRESET;
	spin_unlock_irqrestore(&io->lock, flags);

	for (i = io->entries - 1; i >= 0; --i) {
		usb_block_urb(io->urbs[i]);

		retval = usb_unlink_urb(io->urbs[i]);
		if (retval != -EINPROGRESS
		    && retval != -ENODEV
		    && retval != -EBUSY
		    && retval != -EIDRM)
			dev_warn(&io->dev->dev, "%s, unlink --> %d\n",
				 __func__, retval);
	}
}
EXPORT_SYMBOL_GPL(usb_sg_cancel);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -589,12 +589,13 @@
 	int i, retval;
 
 	spin_lock_irqsave(&io->lock, flags);
-	if (io->status) {
+	if (io->status || io->count == 0) {
 		spin_unlock_irqrestore(&io->lock, flags);
 		return;
 	}
 	/* shut everything down */
 	io->status = -ECONNRESET;
+	io->count++;		/* Keep the request alive until we're done */
 	spin_unlock_irqrestore(&io->lock, flags);
 
 	for (i = io->entries - 1; i >= 0; --i) {
@@ -608,6 +609,12 @@
 			dev_warn(&io->dev->dev, "%s, unlink --> %d\n",
 				 __func__, retval);
 	}
+
+	spin_lock_irqsave(&io->lock, flags);
+	io->count--;
+	if (!io->count)
+		complete(&io->complete);
+	spin_unlock_irqrestore(&io->lock, flags);
 }
 EXPORT_SYMBOL_GPL(usb_sg_cancel);
 
```
