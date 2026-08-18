# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 1819_1
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1819_1`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 4753-4793 of the vulnerable file.

	}

	ext4_inode_resume_unlocked_dio(inode);

	return ret > 0 ? ret2 : ret;
}

static long ext4_zero_range(struct file *file, loff_t offset,
			    loff_t len, int mode)
{
	struct inode *inode = file_inode(file);
	handle_t *handle = NULL;
	unsigned int max_blocks;
	loff_t new_size = 0;
	int ret = 0;
	int flags;
	int credits;
	int partial_begin, partial_end;
	loff_t start, end;
	ext4_lblk_t lblk;
	struct address_space *mapping = inode->i_mapping;
	unsigned int blkbits = inode->i_blkbits;

	trace_ext4_zero_range(inode, offset, len, mode);

	if (!S_ISREG(inode->i_mode))
		return -EINVAL;

	/* Call ext4_force_commit to flush all data in case of data=journal. */
	if (ext4_should_journal_data(inode)) {
		ret = ext4_force_commit(inode->i_sb);
		if (ret)
			return ret;
	}

	/*
	 * Write out all dirty pages to avoid race conditions
	 * Then release them.
	 */
	if (mapping->nrpages && mapping_tagged(mapping, PAGECACHE_TAG_DIRTY)) {
		ret = filemap_write_and_wait_range(mapping, offset,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4770,7 +4770,6 @@
 	int partial_begin, partial_end;
 	loff_t start, end;
 	ext4_lblk_t lblk;
-	struct address_space *mapping = inode->i_mapping;
 	unsigned int blkbits = inode->i_blkbits;
 
 	trace_ext4_zero_range(inode, offset, len, mode);
@@ -4781,17 +4780,6 @@
 	/* Call ext4_force_commit to flush all data in case of data=journal. */
 	if (ext4_should_journal_data(inode)) {
 		ret = ext4_force_commit(inode->i_sb);
-		if (ret)
-			return ret;
-	}
-
-	/*
-	 * Write out all dirty pages to avoid race conditions
-	 * Then release them.
-	 */
-	if (mapping->nrpages && mapping_tagged(mapping, PAGECACHE_TAG_DIRTY)) {
-		ret = filemap_write_and_wait_range(mapping, offset,
-						   offset + len - 1);
 		if (ret)
 			return ret;
 	}
@@ -4856,16 +4844,22 @@
 		flags |= (EXT4_GET_BLOCKS_CONVERT_UNWRITTEN |
 			  EXT4_EX_NOCACHE);
 
-		/* Now release the pages and zero block aligned part of pages*/
-		truncate_pagecache_range(inode, start, end - 1);
-		inode->i_mtime = inode->i_ctime = ext4_current_time(inode);
-
 		/* Wait all existing dio workers, newcomers will block on i_mutex */
 		ext4_inode_block_unlocked_dio(inode);
 		inode_dio_wait(inode);
 
+		/*
+		 * Prevent page faults from reinstantiating pages we have
+		 * released from page cache.
+		 */
+		down_write(&EXT4_I(inode)->i_mmap_sem);
+		/* Now release the pages and zero block aligned part of pages */
+		truncate_pagecache_range(inode, start, end - 1);
+		inode->i_mtime = inode->i_ctime = ext4_current_time(inode);
+
 		ret = ext4_alloc_file_blocks(file, lblk, max_blocks, new_size,
 					     flags, mode);
+		up_write(&EXT4_I(inode)->i_mmap_sem);
 		if (ret)
 			goto out_dio;
 	}
@@ -5524,17 +5518,22 @@
 		goto out_mutex;
 	}
 
-	truncate_pagecache(inode, ioffset);
-
 	/* Wait for existing dio to complete */
 	ext4_inode_block_unlocked_dio(inode);
 	inode_dio_wait(inode);
+
+	/*
+	 * Prevent page faults from reinstantiating pages we have released from
+	 * page cache.
+	 */
+	down_write(&EXT4_I(inode)->i_mmap_sem);
+	truncate_pagecache(inode, ioffset);
 
 	credits = ext4_writepage_trans_blocks(inode);
 	handle = ext4_journal_start(inode, EXT4_HT_TRUNCATE, credits);
 	if (IS_ERR(handle)) {
 		ret = PTR_ERR(handle);
-		goto out_dio;
+		goto out_mmap;
 	}
 
 	down_write(&EXT4_I(inode)->i_data_sem);
@@ -5573,7 +5572,8 @@
 
 out_stop:
 	ext4_journal_stop(handle);
-out_dio:
+out_mmap:
+	up_write(&EXT4_I(inode)->i_mmap_sem);
 	ext4_inode_resume_unlocked_dio(inode);
 out_mutex:
 	mutex_unlock(&inode->i_mutex);
@@ -5660,17 +5660,22 @@
 		goto out_mutex;
 	}
 
-	truncate_pagecache(inode, ioffset);
-
 	/* Wait for existing dio to complete */
 	ext4_inode_block_unlocked_dio(inode);
 	inode_dio_wait(inode);
+
+	/*
+	 * Prevent page faults from reinstantiating pages we have released from
+	 * page cache.
+	 */
+	down_write(&EXT4_I(inode)->i_mmap_sem);
+	truncate_pagecache(inode, ioffset);
 
 	credits = ext4_writepage_trans_blocks(inode);
 	handle = ext4_journal_start(inode, EXT4_HT_TRUNCATE, credits);
 	if (IS_ERR(handle)) {
 		ret = PTR_ERR(handle);
-		goto out_dio;
+		goto out_mmap;
 	}
 
 	/* Expand file to avoid data loss if there is error while shifting */
@@ -5741,7 +5746,8 @@
 
 out_stop:
 	ext4_journal_stop(handle);
-out_dio:
+out_mmap:
+	up_write(&EXT4_I(inode)->i_mmap_sem);
 	ext4_inode_resume_unlocked_dio(inode);
 out_mutex:
 	mutex_unlock(&inode->i_mutex);
```
