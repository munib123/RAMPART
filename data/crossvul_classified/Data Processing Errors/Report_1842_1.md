# CrossVul Fix Pair: Data Processing Errors in c
**Pair ID:** 1842_1
**Vulnerability Class:** Data Processing Errors
**CWE:** CWE-19
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1842_1`)

## Vulnerability Information & PoC

## Description
Data Processing Errors

## Vulnerable Code
```c
Lines 827-867 of the vulnerable file.


	ext4_unregister_li_request(sb);
	dquot_disable(sb, -1, DQUOT_USAGE_ENABLED | DQUOT_LIMITS_ENABLED);

	flush_workqueue(sbi->rsv_conversion_wq);
	destroy_workqueue(sbi->rsv_conversion_wq);

	if (sbi->s_journal) {
		err = jbd2_journal_destroy(sbi->s_journal);
		sbi->s_journal = NULL;
		if (err < 0)
			ext4_abort(sb, "Couldn't clean up the journal");
	}

	ext4_unregister_sysfs(sb);
	ext4_es_unregister_shrinker(sbi);
	del_timer_sync(&sbi->s_err_report);
	ext4_release_system_zone(sb);
	ext4_mb_release(sb);
	ext4_ext_release(sb);
	ext4_xattr_put_super(sb);

	if (!(sb->s_flags & MS_RDONLY)) {
		ext4_clear_feature_journal_needs_recovery(sb);
		es->s_state = cpu_to_le16(sbi->s_mount_state);
	}
	if (!(sb->s_flags & MS_RDONLY))
		ext4_commit_super(sb, 1);

	for (i = 0; i < sbi->s_gdb_count; i++)
		brelse(sbi->s_group_desc[i]);
	kvfree(sbi->s_group_desc);
	kvfree(sbi->s_flex_groups);
	percpu_counter_destroy(&sbi->s_freeclusters_counter);
	percpu_counter_destroy(&sbi->s_freeinodes_counter);
	percpu_counter_destroy(&sbi->s_dirs_counter);
	percpu_counter_destroy(&sbi->s_dirtyclusters_counter);
	brelse(sbi->s_sbh);
#ifdef CONFIG_QUOTA
	for (i = 0; i < EXT4_MAXQUOTAS; i++)
		kfree(sbi->s_qf_names[i]);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -844,7 +844,6 @@
 	ext4_release_system_zone(sb);
 	ext4_mb_release(sb);
 	ext4_ext_release(sb);
-	ext4_xattr_put_super(sb);
 
 	if (!(sb->s_flags & MS_RDONLY)) {
 		ext4_clear_feature_journal_needs_recovery(sb);
@@ -3797,7 +3796,7 @@
 
 no_journal:
 	if (ext4_mballoc_ready) {
-		sbi->s_mb_cache = ext4_xattr_create_cache(sb->s_id);
+		sbi->s_mb_cache = ext4_xattr_create_cache();
 		if (!sbi->s_mb_cache) {
 			ext4_msg(sb, KERN_ERR, "Failed to create an mb_cache");
 			goto failed_mount_wq;
@@ -4027,6 +4026,10 @@
 	if (EXT4_SB(sb)->rsv_conversion_wq)
 		destroy_workqueue(EXT4_SB(sb)->rsv_conversion_wq);
 failed_mount_wq:
+	if (sbi->s_mb_cache) {
+		ext4_xattr_destroy_cache(sbi->s_mb_cache);
+		sbi->s_mb_cache = NULL;
+	}
 	if (sbi->s_journal) {
 		jbd2_journal_destroy(sbi->s_journal);
 		sbi->s_journal = NULL;
```
