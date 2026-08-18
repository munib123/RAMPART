# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 2089_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2089_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 905-946 of the vulnerable file.

/*
 * If the page cache is marked as unsafe or invalid, then we can't rely on
 * the PageUptodate() flag. In this case, we will need to turn off
 * write optimisations that depend on the page contents being correct.
 */
static bool nfs_write_pageuptodate(struct page *page, struct inode *inode)
{
	if (nfs_have_delegated_attributes(inode))
		goto out;
	if (NFS_I(inode)->cache_validity & (NFS_INO_INVALID_DATA|NFS_INO_REVAL_PAGECACHE))
		return false;
out:
	return PageUptodate(page) != 0;
}

/* If we know the page is up to date, and we're not using byte range locks (or
 * if we have the whole file locked for writing), it may be more efficient to
 * extend the write to cover the entire page in order to avoid fragmentation
 * inefficiencies.
 *
 * If the file is opened for synchronous writes or if we have a write delegation
 * from the server then we can just skip the rest of the checks.
 */
static int nfs_can_extend_write(struct file *file, struct page *page, struct inode *inode)
{
	if (file->f_flags & O_DSYNC)
		return 0;
	if (NFS_PROTO(inode)->have_delegation(inode, FMODE_WRITE))
		return 1;
	if (nfs_write_pageuptodate(page, inode) && (inode->i_flock == NULL ||
			(inode->i_flock->fl_start == 0 &&
			inode->i_flock->fl_end == OFFSET_MAX &&
			inode->i_flock->fl_type != F_RDLCK)))
		return 1;
	return 0;
}

/*
 * Update and possibly write a cached page of an NFS file.
 *
 * XXX: Keep an eye on generic_file_read to make sure it doesn't do bad
 * things with a page scheduled for an RPC call (e.g. invalidate it).
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -922,19 +922,20 @@
  * extend the write to cover the entire page in order to avoid fragmentation
  * inefficiencies.
  *
- * If the file is opened for synchronous writes or if we have a write delegation
- * from the server then we can just skip the rest of the checks.
+ * If the file is opened for synchronous writes then we can just skip the rest
+ * of the checks.
  */
 static int nfs_can_extend_write(struct file *file, struct page *page, struct inode *inode)
 {
 	if (file->f_flags & O_DSYNC)
+		return 0;
+	if (!nfs_write_pageuptodate(page, inode))
 		return 0;
 	if (NFS_PROTO(inode)->have_delegation(inode, FMODE_WRITE))
 		return 1;
-	if (nfs_write_pageuptodate(page, inode) && (inode->i_flock == NULL ||
-			(inode->i_flock->fl_start == 0 &&
+	if (inode->i_flock == NULL || (inode->i_flock->fl_start == 0 &&
 			inode->i_flock->fl_end == OFFSET_MAX &&
-			inode->i_flock->fl_type != F_RDLCK)))
+			inode->i_flock->fl_type != F_RDLCK))
 		return 1;
 	return 0;
 }
```
