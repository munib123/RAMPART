# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 1060_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1060_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 745-785 of the vulnerable file.

	} else
		for (unit = 0; unit < PF_UNITS; unit++, pf++) {
			int *conf = *drives[unit];
			if (!conf[D_PRT])
				continue;
			if (pi_init(pf->pi, 0, conf[D_PRT], conf[D_MOD],
				    conf[D_UNI], conf[D_PRO], conf[D_DLY],
				    pf_scratch, PI_PF, verbose, pf->name)) {
				if (pf->disk && !pf_probe(pf)) {
					pf->present = 1;
					k++;
				} else
					pi_release(pf->pi);
			}
		}
	if (k)
		return 0;

	printk("%s: No ATAPI disk detected\n", name);
	for (pf = units, unit = 0; unit < PF_UNITS; pf++, unit++) {
		blk_cleanup_queue(pf->disk->queue);
		pf->disk->queue = NULL;
		blk_mq_free_tag_set(&pf->tag_set);
		put_disk(pf->disk);
	}
	pi_unregister_driver(par_drv);
	return -1;
}

/* The i/o request engine */

static int pf_start(struct pf_unit *pf, int cmd, int b, int c)
{
	int i;
	char io_cmd[12] = { cmd, pf->lun << 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

	for (i = 0; i < 4; i++) {
		io_cmd[5 - i] = b & 0xff;
		b = b >> 8;
	}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -762,6 +762,8 @@
 
 	printk("%s: No ATAPI disk detected\n", name);
 	for (pf = units, unit = 0; unit < PF_UNITS; pf++, unit++) {
+		if (!pf->disk)
+			continue;
 		blk_cleanup_queue(pf->disk->queue);
 		pf->disk->queue = NULL;
 		blk_mq_free_tag_set(&pf->tag_set);
@@ -1029,8 +1031,13 @@
 	pf_busy = 0;
 
 	if (register_blkdev(major, name)) {
-		for (pf = units, unit = 0; unit < PF_UNITS; pf++, unit++)
+		for (pf = units, unit = 0; unit < PF_UNITS; pf++, unit++) {
+			if (!pf->disk)
+				continue;
+			blk_cleanup_queue(pf->disk->queue);
+			blk_mq_free_tag_set(&pf->tag_set);
 			put_disk(pf->disk);
+		}
 		return -EBUSY;
 	}
 
@@ -1051,6 +1058,9 @@
 	int unit;
 	unregister_blkdev(major, name);
 	for (pf = units, unit = 0; unit < PF_UNITS; pf++, unit++) {
+		if (!pf->disk)
+			continue;
+
 		if (pf->present)
 			del_gendisk(pf->disk);
 
```
