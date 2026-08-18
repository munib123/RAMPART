# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 3012_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3012_2`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 784-824 of the vulnerable file.


	f2fs_quota_off_umount(sb);

	/* prevent remaining shrinker jobs */
	mutex_lock(&sbi->umount_mutex);

	/*
	 * We don't need to do checkpoint when superblock is clean.
	 * But, the previous checkpoint was not done by umount, it needs to do
	 * clean checkpoint again.
	 */
	if (is_sbi_flag_set(sbi, SBI_IS_DIRTY) ||
			!is_set_ckpt_flags(sbi, CP_UMOUNT_FLAG)) {
		struct cp_control cpc = {
			.reason = CP_UMOUNT,
		};
		write_checkpoint(sbi, &cpc);
	}

	/* be sure to wait for any on-going discard commands */
	f2fs_wait_discard_bios(sbi);

	if (f2fs_discard_en(sbi) && !sbi->discard_blks) {
		struct cp_control cpc = {
			.reason = CP_UMOUNT | CP_TRIMMED,
		};
		write_checkpoint(sbi, &cpc);
	}

	/* write_checkpoint can update stat informaion */
	f2fs_destroy_stats(sbi);

	/*
	 * normally superblock is clean, so we need to release this.
	 * In addition, EIO will skip do checkpoint, we need this as well.
	 */
	release_ino_entry(sbi, true);

	f2fs_leave_shrinker(sbi);
	mutex_unlock(&sbi->umount_mutex);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -801,7 +801,7 @@
 	}
 
 	/* be sure to wait for any on-going discard commands */
-	f2fs_wait_discard_bios(sbi);
+	f2fs_wait_discard_bios(sbi, true);
 
 	if (f2fs_discard_en(sbi) && !sbi->discard_blks) {
 		struct cp_control cpc = {
```
