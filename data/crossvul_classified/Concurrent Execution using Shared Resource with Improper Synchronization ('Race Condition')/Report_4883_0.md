# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 4883_0
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4883_0`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 1344-1384 of the vulnerable file.

	if (!is_cow) {
		error = xfs_bmapi_read(ip, offset_fsb, end_fsb - offset_fsb,
					&imap, &nimaps, XFS_BMAPI_ENTIRE);
		/*
		 * Truncate an overwrite extent if there's a pending CoW
		 * reservation before the end of this extent.  This
		 * forces us to come back to get_blocks to take care of
		 * the CoW.
		 */
		if (create && direct && nimaps &&
		    imap.br_startblock != HOLESTARTBLOCK &&
		    imap.br_startblock != DELAYSTARTBLOCK &&
		    !ISUNWRITTEN(&imap))
			xfs_reflink_trim_irec_to_next_cow(ip, offset_fsb,
					&imap);
	}
	ASSERT(!need_alloc);
	if (error)
		goto out_unlock;

	/* for DAX, we convert unwritten extents directly */
	if (create &&
	    (!nimaps ||
	     (imap.br_startblock == HOLESTARTBLOCK ||
	      imap.br_startblock == DELAYSTARTBLOCK) ||
	     (IS_DAX(inode) && ISUNWRITTEN(&imap)))) {
		/*
		 * xfs_iomap_write_direct() expects the shared lock. It
		 * is unlocked on return.
		 */
		if (lockmode == XFS_ILOCK_EXCL)
			xfs_ilock_demote(ip, lockmode);

		error = xfs_iomap_write_direct(ip, offset, size,
					       &imap, nimaps);
		if (error)
			return error;
		new = 1;

		trace_xfs_get_blocks_alloc(ip, offset, size,
				ISUNWRITTEN(&imap) ? XFS_IO_UNWRITTEN
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1361,6 +1361,26 @@
 	if (error)
 		goto out_unlock;
 
+	/*
+	 * The only time we can ever safely find delalloc blocks on direct I/O
+	 * is a dio write to post-eof speculative preallocation. All other
+	 * scenarios are indicative of a problem or misuse (such as mixing
+	 * direct and mapped I/O).
+	 *
+	 * The file may be unmapped by the time we get here so we cannot
+	 * reliably fail the I/O based on mapping. Instead, fail the I/O if this
+	 * is a read or a write within eof. Otherwise, carry on but warn as a
+	 * precuation if the file happens to be mapped.
+	 */
+	if (direct && imap.br_startblock == DELAYSTARTBLOCK) {
+		if (!create || offset < i_size_read(VFS_I(ip))) {
+			WARN_ON_ONCE(1);
+			error = -EIO;
+			goto out_unlock;
+		}
+		WARN_ON_ONCE(mapping_mapped(VFS_I(ip)->i_mapping));
+	}
+
 	/* for DAX, we convert unwritten extents directly */
 	if (create &&
 	    (!nimaps ||
@@ -1449,8 +1469,6 @@
 	     (offset >= i_size_read(inode)) ||
 	     (new || ISUNWRITTEN(&imap))))
 		set_buffer_new(bh_result);
-
-	BUG_ON(direct && imap.br_startblock == DELAYSTARTBLOCK);
 
 	return 0;
 
```
