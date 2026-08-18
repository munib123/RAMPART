# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 1472_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1472_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 532-572 of the vulnerable file.

 * 0 on success, -errno on failure.
 */
static int cuse_channel_release(struct inode *inode, struct file *file)
{
	struct fuse_dev *fud = file->private_data;
	struct cuse_conn *cc = fc_to_cc(fud->fc);
	int rc;

	/* remove from the conntbl, no more access from this point on */
	mutex_lock(&cuse_lock);
	list_del_init(&cc->list);
	mutex_unlock(&cuse_lock);

	/* remove device */
	if (cc->dev)
		device_unregister(cc->dev);
	if (cc->cdev) {
		unregister_chrdev_region(cc->cdev->dev, 1);
		cdev_del(cc->cdev);
	}

	rc = fuse_dev_release(inode, file);	/* puts the base reference */

	return rc;
}

static struct file_operations cuse_channel_fops; /* initialized during init */


/**************************************************************************
 * Misc stuff and module initializatiion
 *
 * CUSE exports the same set of attributes to sysfs as fusectl.
 */

static ssize_t cuse_class_waiting_show(struct device *dev,
				       struct device_attribute *attr, char *buf)
{
	struct cuse_conn *cc = dev_get_drvdata(dev);

	return sprintf(buf, "%d\n", atomic_read(&cc->fc.num_waiting));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -549,6 +549,8 @@
 		unregister_chrdev_region(cc->cdev->dev, 1);
 		cdev_del(cc->cdev);
 	}
+	/* Base reference is now owned by "fud" */
+	fuse_conn_put(&cc->fc);
 
 	rc = fuse_dev_release(inode, file);	/* puts the base reference */
 
```
