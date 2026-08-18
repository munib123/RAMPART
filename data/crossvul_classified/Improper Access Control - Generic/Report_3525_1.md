# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 3525_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3525_1`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 1058-1098 of the vulnerable file.

 *	Often contains a pointer.
 *
 *	Returns 0 if successful (some ioctls return positive numbers on
 *	success as well). Returns a negated errno value in case of error.
 *
 *	Note: most ioctls are forward onto the block subsystem or further
 *	down in the scsi subsystem.
 **/
static int sd_ioctl(struct block_device *bdev, fmode_t mode,
		    unsigned int cmd, unsigned long arg)
{
	struct gendisk *disk = bdev->bd_disk;
	struct scsi_disk *sdkp = scsi_disk(disk);
	struct scsi_device *sdp = sdkp->device;
	void __user *p = (void __user *)arg;
	int error;
    
	SCSI_LOG_IOCTL(1, sd_printk(KERN_INFO, sdkp, "sd_ioctl: disk=%s, "
				    "cmd=0x%x\n", disk->disk_name, cmd));

	/*
	 * If we are in the middle of error recovery, don't let anyone
	 * else try and use this device.  Also, if error recovery fails, it
	 * may try and take the device offline, in which case all further
	 * access to the device is prohibited.
	 */
	error = scsi_nonblockable_ioctl(sdp, cmd, p,
					(mode & FMODE_NDELAY) != 0);
	if (!scsi_block_when_processing_errors(sdp) || !error)
		goto out;

	/*
	 * Send SCSI addressing ioctls directly to mid level, send other
	 * ioctls to block level and then onto mid level if they can't be
	 * resolved.
	 */
	switch (cmd) {
		case SCSI_IOCTL_GET_IDLUN:
		case SCSI_IOCTL_GET_BUS_NUMBER:
			error = scsi_ioctl(sdp, cmd, p);
			break;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1075,6 +1075,10 @@
 	SCSI_LOG_IOCTL(1, sd_printk(KERN_INFO, sdkp, "sd_ioctl: disk=%s, "
 				    "cmd=0x%x\n", disk->disk_name, cmd));
 
+	error = scsi_verify_blk_ioctl(bdev, cmd);
+	if (error < 0)
+		return error;
+
 	/*
 	 * If we are in the middle of error recovery, don't let anyone
 	 * else try and use this device.  Also, if error recovery fails, it
@@ -1267,6 +1271,11 @@
 			   unsigned int cmd, unsigned long arg)
 {
 	struct scsi_device *sdev = scsi_disk(bdev->bd_disk)->device;
+	int ret;
+
+	ret = scsi_verify_blk_ioctl(bdev, cmd);
+	if (ret < 0)
+		return ret;
 
 	/*
 	 * If we are in the middle of error recovery, don't let anyone
@@ -1278,8 +1287,6 @@
 		return -ENODEV;
 	       
 	if (sdev->host->hostt->compat_ioctl) {
-		int ret;
-
 		ret = sdev->host->hostt->compat_ioctl(sdev, cmd, (void __user *)arg);
 
 		return ret;
```
