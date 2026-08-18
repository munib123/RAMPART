# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 3640_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3640_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 609-651 of the vulnerable file.


	rc = migrate_huge_page_move_mapping(mapping, newpage, page);
	if (rc)
		return rc;
	migrate_page_copy(newpage, page);

	return 0;
}

static int hugetlbfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct hugetlbfs_sb_info *sbinfo = HUGETLBFS_SB(dentry->d_sb);
	struct hstate *h = hstate_inode(dentry->d_inode);

	buf->f_type = HUGETLBFS_MAGIC;
	buf->f_bsize = huge_page_size(h);
	if (sbinfo) {
		spin_lock(&sbinfo->stat_lock);
		/* If no limits set, just report 0 for max/free/used
		 * blocks, like simple_statfs() */
		if (sbinfo->max_blocks >= 0) {
			buf->f_blocks = sbinfo->max_blocks;
			buf->f_bavail = buf->f_bfree = sbinfo->free_blocks;
			buf->f_files = sbinfo->max_inodes;
			buf->f_ffree = sbinfo->free_inodes;
		}
		spin_unlock(&sbinfo->stat_lock);
	}
	buf->f_namelen = NAME_MAX;
	return 0;
}

static void hugetlbfs_put_super(struct super_block *sb)
{
	struct hugetlbfs_sb_info *sbi = HUGETLBFS_SB(sb);

	if (sbi) {
		sb->s_fs_info = NULL;
		kfree(sbi);
	}
}

static inline int hugetlbfs_dec_free_inodes(struct hugetlbfs_sb_info *sbinfo)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -626,9 +626,15 @@
 		spin_lock(&sbinfo->stat_lock);
 		/* If no limits set, just report 0 for max/free/used
 		 * blocks, like simple_statfs() */
-		if (sbinfo->max_blocks >= 0) {
-			buf->f_blocks = sbinfo->max_blocks;
-			buf->f_bavail = buf->f_bfree = sbinfo->free_blocks;
+		if (sbinfo->spool) {
+			long free_pages;
+
+			spin_lock(&sbinfo->spool->lock);
+			buf->f_blocks = sbinfo->spool->max_hpages;
+			free_pages = sbinfo->spool->max_hpages
+				- sbinfo->spool->used_hpages;
+			buf->f_bavail = buf->f_bfree = free_pages;
+			spin_unlock(&sbinfo->spool->lock);
 			buf->f_files = sbinfo->max_inodes;
 			buf->f_ffree = sbinfo->free_inodes;
 		}
@@ -644,6 +650,10 @@
 
 	if (sbi) {
 		sb->s_fs_info = NULL;
+
+		if (sbi->spool)
+			hugepage_put_subpool(sbi->spool);
+
 		kfree(sbi);
 	}
 }
@@ -874,10 +884,14 @@
 	sb->s_fs_info = sbinfo;
 	sbinfo->hstate = config.hstate;
 	spin_lock_init(&sbinfo->stat_lock);
-	sbinfo->max_blocks = config.nr_blocks;
-	sbinfo->free_blocks = config.nr_blocks;
 	sbinfo->max_inodes = config.nr_inodes;
 	sbinfo->free_inodes = config.nr_inodes;
+	sbinfo->spool = NULL;
+	if (config.nr_blocks != -1) {
+		sbinfo->spool = hugepage_new_subpool(config.nr_blocks);
+		if (!sbinfo->spool)
+			goto out_free;
+	}
 	sb->s_maxbytes = MAX_LFS_FILESIZE;
 	sb->s_blocksize = huge_page_size(config.hstate);
 	sb->s_blocksize_bits = huge_page_shift(config.hstate);
@@ -896,36 +910,10 @@
 	sb->s_root = root;
 	return 0;
 out_free:
+	if (sbinfo->spool)
+		kfree(sbinfo->spool);
 	kfree(sbinfo);
 	return -ENOMEM;
-}
-
-int hugetlb_get_quota(struct address_space *mapping, long delta)
-{
-	int ret = 0;
-	struct hugetlbfs_sb_info *sbinfo = HUGETLBFS_SB(mapping->host->i_sb);
-
-	if (sbinfo->free_blocks > -1) {
-		spin_lock(&sbinfo->stat_lock);
-		if (sbinfo->free_blocks - delta >= 0)
-			sbinfo->free_blocks -= delta;
-		else
-			ret = -ENOMEM;
-		spin_unlock(&sbinfo->stat_lock);
-	}
-
-	return ret;
-}
-
-void hugetlb_put_quota(struct address_space *mapping, long delta)
-{
-	struct hugetlbfs_sb_info *sbinfo = HUGETLBFS_SB(mapping->host->i_sb);
-
-	if (sbinfo->free_blocks > -1) {
-		spin_lock(&sbinfo->stat_lock);
-		sbinfo->free_blocks += delta;
-		spin_unlock(&sbinfo->stat_lock);
-	}
 }
 
 static struct dentry *hugetlbfs_mount(struct file_system_type *fs_type,
```
