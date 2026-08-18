# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 1819_3
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1819_3`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 3606-3646 of the vulnerable file.

	 * to end after the page that contains i_size
	 */
	if (offset + length > inode->i_size) {
		length = inode->i_size +
		   PAGE_CACHE_SIZE - (inode->i_size & (PAGE_CACHE_SIZE - 1)) -
		   offset;
	}

	if (offset & (sb->s_blocksize - 1) ||
	    (offset + length) & (sb->s_blocksize - 1)) {
		/*
		 * Attach jinode to inode for jbd2 if we do any zeroing of
		 * partial block
		 */
		ret = ext4_inode_attach_jinode(inode);
		if (ret < 0)
			goto out_mutex;

	}

	first_block_offset = round_up(offset, sb->s_blocksize);
	last_block_offset = round_down((offset + length), sb->s_blocksize) - 1;

	/* Now release the pages and zero block aligned part of pages*/
	if (last_block_offset > first_block_offset)
		truncate_pagecache_range(inode, first_block_offset,
					 last_block_offset);

	/* Wait all existing dio workers, newcomers will block on i_mutex */
	ext4_inode_block_unlocked_dio(inode);
	inode_dio_wait(inode);

	if (ext4_test_inode_flag(inode, EXT4_INODE_EXTENTS))
		credits = ext4_writepage_trans_blocks(inode);
	else
		credits = ext4_blocks_for_truncate(inode);
	handle = ext4_journal_start(inode, EXT4_HT_TRUNCATE, credits);
	if (IS_ERR(handle)) {
		ret = PTR_ERR(handle);
		ext4_std_error(sb, ret);
		goto out_dio;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3623,6 +3623,15 @@
 
 	}
 
+	/* Wait all existing dio workers, newcomers will block on i_mutex */
+	ext4_inode_block_unlocked_dio(inode);
+	inode_dio_wait(inode);
+
+	/*
+	 * Prevent page faults from reinstantiating pages we have released from
+	 * page cache.
+	 */
+	down_write(&EXT4_I(inode)->i_mmap_sem);
 	first_block_offset = round_up(offset, sb->s_blocksize);
 	last_block_offset = round_down((offset + length), sb->s_blocksize) - 1;
 
@@ -3630,10 +3639,6 @@
 	if (last_block_offset > first_block_offset)
 		truncate_pagecache_range(inode, first_block_offset,
 					 last_block_offset);
-
-	/* Wait all existing dio workers, newcomers will block on i_mutex */
-	ext4_inode_block_unlocked_dio(inode);
-	inode_dio_wait(inode);
 
 	if (ext4_test_inode_flag(inode, EXT4_INODE_EXTENTS))
 		credits = ext4_writepage_trans_blocks(inode);
@@ -3680,16 +3685,12 @@
 	if (IS_SYNC(inode))
 		ext4_handle_sync(handle);
 
-	/* Now release the pages again to reduce race window */
-	if (last_block_offset > first_block_offset)
-		truncate_pagecache_range(inode, first_block_offset,
-					 last_block_offset);
-
 	inode->i_mtime = inode->i_ctime = ext4_current_time(inode);
 	ext4_mark_inode_dirty(handle, inode);
 out_stop:
 	ext4_journal_stop(handle);
 out_dio:
+	up_write(&EXT4_I(inode)->i_mmap_sem);
 	ext4_inode_resume_unlocked_dio(inode);
 out_mutex:
 	mutex_unlock(&inode->i_mutex);
@@ -4823,6 +4824,7 @@
 			} else
 				ext4_wait_for_tail_page_commit(inode);
 		}
+		down_write(&EXT4_I(inode)->i_mmap_sem);
 		/*
 		 * Truncate pagecache after we've waited for commit
 		 * in data=journal mode to make pages freeable.
@@ -4830,6 +4832,7 @@
 		truncate_pagecache(inode, inode->i_size);
 		if (shrink)
 			ext4_truncate(inode);
+		up_write(&EXT4_I(inode)->i_mmap_sem);
 	}
 
 	if (!rc) {
@@ -5278,6 +5281,8 @@
 
 	sb_start_pagefault(inode->i_sb);
 	file_update_time(vma->vm_file);
+
+	down_read(&EXT4_I(inode)->i_mmap_sem);
 	/* Delalloc case is easy... */
 	if (test_opt(inode->i_sb, DELALLOC) &&
 	    !ext4_should_journal_data(inode) &&
@@ -5347,6 +5352,19 @@
 out_ret:
 	ret = block_page_mkwrite_return(ret);
 out:
+	up_read(&EXT4_I(inode)->i_mmap_sem);
 	sb_end_pagefault(inode->i_sb);
 	return ret;
 }
+
+int ext4_filemap_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
+{
+	struct inode *inode = file_inode(vma->vm_file);
+	int err;
+
+	down_read(&EXT4_I(inode)->i_mmap_sem);
+	err = filemap_fault(vma, vmf);
+	up_read(&EXT4_I(inode)->i_mmap_sem);
+
+	return err;
+}
```
