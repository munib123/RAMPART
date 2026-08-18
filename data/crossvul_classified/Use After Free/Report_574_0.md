# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 574_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `574_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 1564-1604 of the vulnerable file.

#endif

static int lo_open(struct block_device *bdev, fmode_t mode)
{
	struct loop_device *lo;
	int err = 0;

	mutex_lock(&loop_index_mutex);
	lo = bdev->bd_disk->private_data;
	if (!lo) {
		err = -ENXIO;
		goto out;
	}

	atomic_inc(&lo->lo_refcnt);
out:
	mutex_unlock(&loop_index_mutex);
	return err;
}

static void lo_release(struct gendisk *disk, fmode_t mode)
{
	struct loop_device *lo = disk->private_data;
	int err;

	if (atomic_dec_return(&lo->lo_refcnt))
		return;

	mutex_lock(&lo->lo_ctl_mutex);
	if (lo->lo_flags & LO_FLAGS_AUTOCLEAR) {
		/*
		 * In autoclear mode, stop the loop thread
		 * and remove configuration after last close.
		 */
		err = loop_clr_fd(lo);
		if (!err)
			return;
	} else if (lo->lo_state == Lo_bound) {
		/*
		 * Otherwise keep thread (if running) and config,
		 * but flush possible ongoing bios in thread.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1581,9 +1581,8 @@
 	return err;
 }
 
-static void lo_release(struct gendisk *disk, fmode_t mode)
-{
-	struct loop_device *lo = disk->private_data;
+static void __lo_release(struct loop_device *lo)
+{
 	int err;
 
 	if (atomic_dec_return(&lo->lo_refcnt))
@@ -1608,6 +1607,13 @@
 	}
 
 	mutex_unlock(&lo->lo_ctl_mutex);
+}
+
+static void lo_release(struct gendisk *disk, fmode_t mode)
+{
+	mutex_lock(&loop_index_mutex);
+	__lo_release(disk->private_data);
+	mutex_unlock(&loop_index_mutex);
 }
 
 static const struct block_device_operations lo_fops = {
```
