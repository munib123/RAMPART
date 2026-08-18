# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 1223_3
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1223_3`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 396-455 of the vulnerable file.

	 */
	dev->flush_bio = bio_alloc_bioset(GFP_KERNEL, 0, NULL);
	if (!dev->flush_bio) {
		kfree(dev);
		return ERR_PTR(-ENOMEM);
	}

	INIT_LIST_HEAD(&dev->dev_list);
	INIT_LIST_HEAD(&dev->dev_alloc_list);
	INIT_LIST_HEAD(&dev->resized_list);

	spin_lock_init(&dev->io_lock);

	atomic_set(&dev->reada_in_flight, 0);
	atomic_set(&dev->dev_stats_ccnt, 0);
	btrfs_device_data_ordered_init(dev);
	INIT_RADIX_TREE(&dev->reada_zones, GFP_NOFS & ~__GFP_DIRECT_RECLAIM);
	INIT_RADIX_TREE(&dev->reada_extents, GFP_NOFS & ~__GFP_DIRECT_RECLAIM);

	return dev;
}

/*
 * Find a device specified by @devid or @uuid in the list of @fs_devices, or
 * return NULL.
 *
 * If devid and uuid are both specified, the match must be exact, otherwise
 * only devid is used.
 */
static struct btrfs_device *find_device(struct btrfs_fs_devices *fs_devices,
		u64 devid, const u8 *uuid)
{
	struct btrfs_device *dev;

	list_for_each_entry(dev, &fs_devices->devices, dev_list) {
		if (dev->devid == devid &&
		    (!uuid || !memcmp(dev->uuid, uuid, BTRFS_UUID_SIZE))) {
			return dev;
		}
	}
	return NULL;
}

static noinline struct btrfs_fs_devices *find_fsid(
		const u8 *fsid, const u8 *metadata_fsid)
{
	struct btrfs_fs_devices *fs_devices;

	ASSERT(fsid);

	if (metadata_fsid) {
		/*
		 * Handle scanned device having completed its fsid change but
		 * belonging to a fs_devices that was created by first scanning
		 * a device which didn't have its fsid/metadata_uuid changed
		 * at all and the CHANGING_FSID_V2 flag set.
		 */
		list_for_each_entry(fs_devices, &fs_uuids, fs_list) {
			if (fs_devices->fsid_change &&
			    memcmp(metadata_fsid, fs_devices->fsid,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -415,27 +415,6 @@
 	return dev;
 }
 
-/*
- * Find a device specified by @devid or @uuid in the list of @fs_devices, or
- * return NULL.
- *
- * If devid and uuid are both specified, the match must be exact, otherwise
- * only devid is used.
- */
-static struct btrfs_device *find_device(struct btrfs_fs_devices *fs_devices,
-		u64 devid, const u8 *uuid)
-{
-	struct btrfs_device *dev;
-
-	list_for_each_entry(dev, &fs_devices->devices, dev_list) {
-		if (dev->devid == devid &&
-		    (!uuid || !memcmp(dev->uuid, uuid, BTRFS_UUID_SIZE))) {
-			return dev;
-		}
-	}
-	return NULL;
-}
-
 static noinline struct btrfs_fs_devices *find_fsid(
 		const u8 *fsid, const u8 *metadata_fsid)
 {
@@ -984,8 +963,8 @@
 		device = NULL;
 	} else {
 		mutex_lock(&fs_devices->device_list_mutex);
-		device = find_device(fs_devices, devid,
-				disk_super->dev_item.uuid);
+		device = btrfs_find_device(fs_devices, devid,
+				disk_super->dev_item.uuid, NULL, false);
 
 		/*
 		 * If this disk has been pulled into an fs devices created by
@@ -2402,10 +2381,10 @@
 	dev_uuid = disk_super->dev_item.uuid;
 	if (btrfs_fs_incompat(fs_info, METADATA_UUID))
 		device = btrfs_find_device(fs_info->fs_devices, devid, dev_uuid,
-					   disk_super->metadata_uuid);
+					   disk_super->metadata_uuid, true);
 	else
 		device = btrfs_find_device(fs_info->fs_devices, devid, dev_uuid,
-					   disk_super->fsid);
+					   disk_super->fsid, true);
 
 	brelse(bh);
 	if (!device)
@@ -2425,7 +2404,7 @@
 
 	if (devid) {
 		device = btrfs_find_device(fs_info->fs_devices, devid, NULL,
-					   NULL);
+					   NULL, true);
 		if (!device)
 			return ERR_PTR(-ENOENT);
 		return device;
@@ -2568,7 +2547,7 @@
 		read_extent_buffer(leaf, fs_uuid, btrfs_device_fsid(dev_item),
 				   BTRFS_FSID_SIZE);
 		device = btrfs_find_device(fs_info->fs_devices, devid, dev_uuid,
-					   fs_uuid);
+					   fs_uuid, true);
 		BUG_ON(!device); /* Logic error */
 
 		if (device->fs_devices->seeding) {
@@ -6621,19 +6600,36 @@
 	return BLK_STS_OK;
 }
 
+/*
+ * Find a device specified by @devid or @uuid in the list of @fs_devices, or
+ * return NULL.
+ *
+ * If devid and uuid are both specified, the match must be exact, otherwise
+ * only devid is used.
+ *
+ * If @seed is true, traverse through the seed devices.
+ */
 struct btrfs_device *btrfs_find_device(struct btrfs_fs_devices *fs_devices,
-				       u64 devid, u8 *uuid, u8 *fsid)
+				       u64 devid, u8 *uuid, u8 *fsid,
+				       bool seed)
 {
 	struct btrfs_device *device;
 
 	while (fs_devices) {
 		if (!fsid ||
 		    !memcmp(fs_devices->metadata_uuid, fsid, BTRFS_FSID_SIZE)) {
-			device = find_device(fs_devices, devid, uuid);
-			if (device)
-				return device;
-		}
-		fs_devices = fs_devices->seed;
+			list_for_each_entry(device, &fs_devices->devices,
+					    dev_list) {
+				if (device->devid == devid &&
+				    (!uuid || memcmp(device->uuid, uuid,
+						     BTRFS_UUID_SIZE) == 0))
+					return device;
+			}
+		}
+		if (seed)
+			fs_devices = fs_devices->seed;
+		else
+			return NULL;
 	}
 	return NULL;
 }
@@ -6879,7 +6875,7 @@
 				   btrfs_stripe_dev_uuid_nr(chunk, i),
 				   BTRFS_UUID_SIZE);
 		map->stripes[i].dev = btrfs_find_device(fs_info->fs_devices,
-							devid, uuid, NULL);
+							devid, uuid, NULL, true);
 		if (!map->stripes[i].dev &&
 		    !btrfs_test_opt(fs_info, DEGRADED)) {
 			free_extent_map(em);
@@ -7019,7 +7015,7 @@
 	}
 
 	device = btrfs_find_device(fs_info->fs_devices, devid, dev_uuid,
-				   fs_uuid);
+				   fs_uuid, true);
 	if (!device) {
 		if (!btrfs_test_opt(fs_info, DEGRADED)) {
 			btrfs_report_missing_device(fs_info, devid,
@@ -7609,7 +7605,8 @@
 	int i;
 
 	mutex_lock(&fs_devices->device_list_mutex);
-	dev = btrfs_find_device(fs_info->fs_devices, stats->devid, NULL, NULL);
+	dev = btrfs_find_device(fs_info->fs_devices, stats->devid, NULL, NULL,
+				true);
 	mutex_unlock(&fs_devices->device_list_mutex);
 
 	if (!dev) {
@@ -7823,7 +7820,7 @@
 	}
 
 	/* Make sure no dev extent is beyond device bondary */
-	dev = btrfs_find_device(fs_info->fs_devices, devid, NULL, NULL);
+	dev = btrfs_find_device(fs_info->fs_devices, devid, NULL, NULL, true);
 	if (!dev) {
 		btrfs_err(fs_info, "failed to find devid %llu", devid);
 		ret = -EUCLEAN;
@@ -7832,7 +7829,8 @@
 
 	/* It's possible this device is a dummy for seed device */
 	if (dev->disk_total_bytes == 0) {
-		dev = find_device(fs_info->fs_devices->seed, devid, NULL);
+		dev = btrfs_find_device(fs_info->fs_devices->seed, devid, NULL,
+					NULL, false);
 		if (!dev) {
 			btrfs_err(fs_info, "failed to find seed devid %llu",
 				  devid);
```
