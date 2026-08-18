# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 3021_0
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3021_0`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 115-155 of the vulnerable file.

				goto bail;
			}
			memcpy(kaddr + (bh_result->b_size * iblock),
			       buffer_cache_bh->b_data,
			       bh_result->b_size);
			kunmap_atomic(kaddr);
			set_buffer_uptodate(bh_result);
		}
		brelse(buffer_cache_bh);
	}

	map_bh(bh_result, inode->i_sb,
	       le64_to_cpu(fe->id2.i_list.l_recs[0].e_blkno) + iblock);

	err = 0;

bail:
	brelse(bh);

	return err;
}

int ocfs2_get_block(struct inode *inode, sector_t iblock,
		    struct buffer_head *bh_result, int create)
{
	int err = 0;
	unsigned int ext_flags;
	u64 max_blocks = bh_result->b_size >> inode->i_blkbits;
	u64 p_blkno, count, past_eof;
	struct ocfs2_super *osb = OCFS2_SB(inode->i_sb);

	trace_ocfs2_get_block((unsigned long long)OCFS2_I(inode)->ip_blkno,
			      (unsigned long long)iblock, bh_result, create);

	if (OCFS2_I(inode)->ip_flags & OCFS2_INODE_SYSTEM_FILE)
		mlog(ML_NOTICE, "get_block on system inode 0x%p (%lu)\n",
		     inode, inode->i_ino);

	if (S_ISLNK(inode->i_mode)) {
		/* this always does I/O for some reason. */
		err = ocfs2_symlink_get_block(inode, iblock, bh_result, create);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -132,6 +132,19 @@
 	brelse(bh);
 
 	return err;
+}
+
+static int ocfs2_lock_get_block(struct inode *inode, sector_t iblock,
+		    struct buffer_head *bh_result, int create)
+{
+	int ret = 0;
+	struct ocfs2_inode_info *oi = OCFS2_I(inode);
+
+	down_read(&oi->ip_alloc_sem);
+	ret = ocfs2_get_block(inode, iblock, bh_result, create);
+	up_read(&oi->ip_alloc_sem);
+
+	return ret;
 }
 
 int ocfs2_get_block(struct inode *inode, sector_t iblock,
@@ -2128,7 +2141,7 @@
  * called like this: dio->get_blocks(dio->inode, fs_startblk,
  * 					fs_count, map_bh, dio->rw == WRITE);
  */
-static int ocfs2_dio_get_block(struct inode *inode, sector_t iblock,
+static int ocfs2_dio_wr_get_block(struct inode *inode, sector_t iblock,
 			       struct buffer_head *bh_result, int create)
 {
 	struct ocfs2_super *osb = OCFS2_SB(inode->i_sb);
@@ -2154,12 +2167,9 @@
 	 * while file size will be changed.
 	 */
 	if (pos + total_len <= i_size_read(inode)) {
-		down_read(&oi->ip_alloc_sem);
+
 		/* This is the fast path for re-write. */
-		ret = ocfs2_get_block(inode, iblock, bh_result, create);
-
-		up_read(&oi->ip_alloc_sem);
-
+		ret = ocfs2_lock_get_block(inode, iblock, bh_result, create);
 		if (buffer_mapped(bh_result) &&
 		    !buffer_new(bh_result) &&
 		    ret == 0)
@@ -2424,9 +2434,9 @@
 		return 0;
 
 	if (iov_iter_rw(iter) == READ)
-		get_block = ocfs2_get_block;
+		get_block = ocfs2_lock_get_block;
 	else
-		get_block = ocfs2_dio_get_block;
+		get_block = ocfs2_dio_wr_get_block;
 
 	return __blockdev_direct_IO(iocb, inode, inode->i_sb->s_bdev,
 				    iter, get_block,
```
