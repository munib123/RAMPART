# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 1061_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1061_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 297-337 of the vulnerable file.


static const struct blk_mq_ops pcd_mq_ops = {
	.queue_rq	= pcd_queue_rq,
};

static void pcd_init_units(void)
{
	struct pcd_unit *cd;
	int unit;

	pcd_drive_count = 0;
	for (unit = 0, cd = pcd; unit < PCD_UNITS; unit++, cd++) {
		struct gendisk *disk = alloc_disk(1);

		if (!disk)
			continue;

		disk->queue = blk_mq_init_sq_queue(&cd->tag_set, &pcd_mq_ops,
						   1, BLK_MQ_F_SHOULD_MERGE);
		if (IS_ERR(disk->queue)) {
			disk->queue = NULL;
			continue;
		}

		INIT_LIST_HEAD(&cd->rq_list);
		disk->queue->queuedata = cd;
		blk_queue_bounce_limit(disk->queue, BLK_BOUNCE_HIGH);
		cd->disk = disk;
		cd->pi = &cd->pia;
		cd->present = 0;
		cd->last_sense = 0;
		cd->changed = 1;
		cd->drive = (*drives[unit])[D_SLV];
		if ((*drives[unit])[D_PRT])
			pcd_drive_count++;

		cd->name = &cd->info.name[0];
		snprintf(cd->name, sizeof(cd->info.name), "%s%d", name, unit);
		cd->info.ops = &pcd_dops;
		cd->info.handle = cd;
		cd->info.speed = 0;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -314,6 +314,7 @@
 		disk->queue = blk_mq_init_sq_queue(&cd->tag_set, &pcd_mq_ops,
 						   1, BLK_MQ_F_SHOULD_MERGE);
 		if (IS_ERR(disk->queue)) {
+			put_disk(disk);
 			disk->queue = NULL;
 			continue;
 		}
@@ -750,6 +751,8 @@
 
 	printk("%s: No CD-ROM drive found\n", name);
 	for (unit = 0, cd = pcd; unit < PCD_UNITS; unit++, cd++) {
+		if (!cd->disk)
+			continue;
 		blk_cleanup_queue(cd->disk->queue);
 		cd->disk->queue = NULL;
 		blk_mq_free_tag_set(&cd->tag_set);
@@ -1010,8 +1013,14 @@
 	pcd_probe_capabilities();
 
 	if (register_blkdev(major, name)) {
-		for (unit = 0, cd = pcd; unit < PCD_UNITS; unit++, cd++)
+		for (unit = 0, cd = pcd; unit < PCD_UNITS; unit++, cd++) {
+			if (!cd->disk)
+				continue;
+
+			blk_cleanup_queue(cd->disk->queue);
+			blk_mq_free_tag_set(&cd->tag_set);
 			put_disk(cd->disk);
+		}
 		return -EBUSY;
 	}
 
@@ -1032,6 +1041,9 @@
 	int unit;
 
 	for (unit = 0, cd = pcd; unit < PCD_UNITS; unit++, cd++) {
+		if (!cd->disk)
+			continue;
+
 		if (cd->present) {
 			del_gendisk(cd->disk);
 			pi_release(cd->pi);
```
