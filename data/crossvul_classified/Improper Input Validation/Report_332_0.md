# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 332_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `332_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 379-420 of the vulnerable file.

	return retval;
}

static int yurex_release(struct inode *inode, struct file *file)
{
	struct usb_yurex *dev;

	dev = file->private_data;
	if (dev == NULL)
		return -ENODEV;

	/* decrement the count on our device */
	kref_put(&dev->kref, yurex_delete);
	return 0;
}

static ssize_t yurex_read(struct file *file, char __user *buffer, size_t count,
			  loff_t *ppos)
{
	struct usb_yurex *dev;
	int retval = 0;
	int bytes_read = 0;
	char in_buffer[20];
	unsigned long flags;

	dev = file->private_data;

	mutex_lock(&dev->io_mutex);
	if (!dev->interface) {		/* already disconnected */
		retval = -ENODEV;
		goto exit;
	}

	spin_lock_irqsave(&dev->lock, flags);
	bytes_read = snprintf(in_buffer, 20, "%lld\n", dev->bbu);
	spin_unlock_irqrestore(&dev->lock, flags);

	if (*ppos < bytes_read) {
		if (copy_to_user(buffer, in_buffer + *ppos, bytes_read - *ppos))
			retval = -EFAULT;
		else {
			retval = bytes_read - *ppos;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -396,8 +396,7 @@
 			  loff_t *ppos)
 {
 	struct usb_yurex *dev;
-	int retval = 0;
-	int bytes_read = 0;
+	int len = 0;
 	char in_buffer[20];
 	unsigned long flags;
 
@@ -405,26 +404,16 @@
 
 	mutex_lock(&dev->io_mutex);
 	if (!dev->interface) {		/* already disconnected */
-		retval = -ENODEV;
-		goto exit;
+		mutex_unlock(&dev->io_mutex);
+		return -ENODEV;
 	}
 
 	spin_lock_irqsave(&dev->lock, flags);
-	bytes_read = snprintf(in_buffer, 20, "%lld\n", dev->bbu);
+	len = snprintf(in_buffer, 20, "%lld\n", dev->bbu);
 	spin_unlock_irqrestore(&dev->lock, flags);
-
-	if (*ppos < bytes_read) {
-		if (copy_to_user(buffer, in_buffer + *ppos, bytes_read - *ppos))
-			retval = -EFAULT;
-		else {
-			retval = bytes_read - *ppos;
-			*ppos += bytes_read;
-		}
-	}
-
-exit:
 	mutex_unlock(&dev->io_mutex);
-	return retval;
+
+	return simple_read_from_buffer(buffer, count, ppos, in_buffer, len);
 }
 
 static ssize_t yurex_write(struct file *file, const char __user *user_buffer,
```
