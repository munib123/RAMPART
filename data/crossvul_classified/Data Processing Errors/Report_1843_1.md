# CrossVul Fix Pair: Data Processing Errors in c
**Pair ID:** 1843_1
**Vulnerability Class:** Data Processing Errors
**CWE:** CWE-19
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1843_1`)

## Vulnerability Information & PoC

## Description
Data Processing Errors

## Vulnerable Code
```c
Lines 114-154 of the vulnerable file.

	es->s_inode_size = cpu_to_le16(EXT2_GOOD_OLD_INODE_SIZE);
	es->s_rev_level = cpu_to_le32(EXT2_DYNAMIC_REV);
	/* leave es->s_feature_*compat flags alone */
	/* es->s_uuid will be set by e2fsck if empty */

	/*
	 * The rest of the superblock fields should be zero, and if not it
	 * means they are likely already in use, so leave them alone.  We
	 * can leave it up to e2fsck to clean up any inconsistencies there.
	 */
}

static void ext2_put_super (struct super_block * sb)
{
	int db_count;
	int i;
	struct ext2_sb_info *sbi = EXT2_SB(sb);

	dquot_disable(sb, -1, DQUOT_USAGE_ENABLED | DQUOT_LIMITS_ENABLED);

	ext2_xattr_put_super(sb);
	if (!(sb->s_flags & MS_RDONLY)) {
		struct ext2_super_block *es = sbi->s_es;

		spin_lock(&sbi->s_lock);
		es->s_state = cpu_to_le16(sbi->s_mount_state);
		spin_unlock(&sbi->s_lock);
		ext2_sync_super(sb, es, 1);
	}
	db_count = sbi->s_gdb_count;
	for (i = 0; i < db_count; i++)
		if (sbi->s_group_desc[i])
			brelse (sbi->s_group_desc[i]);
	kfree(sbi->s_group_desc);
	kfree(sbi->s_debts);
	percpu_counter_destroy(&sbi->s_freeblocks_counter);
	percpu_counter_destroy(&sbi->s_freeinodes_counter);
	percpu_counter_destroy(&sbi->s_dirs_counter);
	brelse (sbi->s_sbh);
	sb->s_fs_info = NULL;
	kfree(sbi->s_blockgroup_lock);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -131,7 +131,10 @@
 
 	dquot_disable(sb, -1, DQUOT_USAGE_ENABLED | DQUOT_LIMITS_ENABLED);
 
-	ext2_xattr_put_super(sb);
+	if (sbi->s_mb_cache) {
+		ext2_xattr_destroy_cache(sbi->s_mb_cache);
+		sbi->s_mb_cache = NULL;
+	}
 	if (!(sb->s_flags & MS_RDONLY)) {
 		struct ext2_super_block *es = sbi->s_es;
 
@@ -1104,6 +1107,14 @@
 		ext2_msg(sb, KERN_ERR, "error: insufficient memory");
 		goto failed_mount3;
 	}
+
+#ifdef CONFIG_EXT2_FS_XATTR
+	sbi->s_mb_cache = ext2_xattr_create_cache();
+	if (!sbi->s_mb_cache) {
+		ext2_msg(sb, KERN_ERR, "Failed to create an mb_cache");
+		goto failed_mount3;
+	}
+#endif
 	/*
 	 * set up enough so that it can read an inode
 	 */
@@ -1149,6 +1160,8 @@
 			sb->s_id);
 	goto failed_mount;
 failed_mount3:
+	if (sbi->s_mb_cache)
+		ext2_xattr_destroy_cache(sbi->s_mb_cache);
 	percpu_counter_destroy(&sbi->s_freeblocks_counter);
 	percpu_counter_destroy(&sbi->s_freeinodes_counter);
 	percpu_counter_destroy(&sbi->s_dirs_counter);
@@ -1555,20 +1568,17 @@
 
 static int __init init_ext2_fs(void)
 {
-	int err = init_ext2_xattr();
+	int err;
+
+	err = init_inodecache();
 	if (err)
 		return err;
-	err = init_inodecache();
-	if (err)
-		goto out1;
         err = register_filesystem(&ext2_fs_type);
 	if (err)
 		goto out;
 	return 0;
 out:
 	destroy_inodecache();
-out1:
-	exit_ext2_xattr();
 	return err;
 }
 
@@ -1576,7 +1586,6 @@
 {
 	unregister_filesystem(&ext2_fs_type);
 	destroy_inodecache();
-	exit_ext2_xattr();
 }
 
 MODULE_AUTHOR("Remy Card and others");
```
