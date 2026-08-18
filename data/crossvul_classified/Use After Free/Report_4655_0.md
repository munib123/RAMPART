# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 4655_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4655_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 984-1024 of the vulnerable file.

	if (!uid_valid(inode->i_uid) || !gid_valid(inode->i_gid))
		return -EOVERFLOW;

	if (!sysctl_protected_hardlinks)
		return 0;

	/* Source inode owner (or CAP_FOWNER) can hardlink all they like,
	 * otherwise, it must be a safe source.
	 */
	if (safe_hardlink_source(inode) || inode_owner_or_capable(inode))
		return 0;

	audit_log_path_denied(AUDIT_ANOM_LINK, "linkat");
	return -EPERM;
}

/**
 * may_create_in_sticky - Check whether an O_CREAT open in a sticky directory
 *			  should be allowed, or not, on files that already
 *			  exist.
 * @dir: the sticky parent directory
 * @inode: the inode of the file to open
 *
 * Block an O_CREAT open of a FIFO (or a regular file) when:
 *   - sysctl_protected_fifos (or sysctl_protected_regular) is enabled
 *   - the file already exists
 *   - we are in a sticky directory
 *   - we don't own the file
 *   - the owner of the directory doesn't own the file
 *   - the directory is world writable
 * If the sysctl_protected_fifos (or sysctl_protected_regular) is set to 2
 * the directory doesn't have to be world writable: being group writable will
 * be enough.
 *
 * Returns 0 if the open is allowed, -ve on error.
 */
static int may_create_in_sticky(struct dentry * const dir,
				struct inode * const inode)
{
	if ((!sysctl_protected_fifos && S_ISFIFO(inode->i_mode)) ||
	    (!sysctl_protected_regular && S_ISREG(inode->i_mode)) ||
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1001,7 +1001,8 @@
  * may_create_in_sticky - Check whether an O_CREAT open in a sticky directory
  *			  should be allowed, or not, on files that already
  *			  exist.
- * @dir: the sticky parent directory
+ * @dir_mode: mode bits of directory
+ * @dir_uid: owner of directory
  * @inode: the inode of the file to open
  *
  * Block an O_CREAT open of a FIFO (or a regular file) when:
@@ -1017,18 +1018,18 @@
  *
  * Returns 0 if the open is allowed, -ve on error.
  */
-static int may_create_in_sticky(struct dentry * const dir,
+static int may_create_in_sticky(umode_t dir_mode, kuid_t dir_uid,
 				struct inode * const inode)
 {
 	if ((!sysctl_protected_fifos && S_ISFIFO(inode->i_mode)) ||
 	    (!sysctl_protected_regular && S_ISREG(inode->i_mode)) ||
-	    likely(!(dir->d_inode->i_mode & S_ISVTX)) ||
-	    uid_eq(inode->i_uid, dir->d_inode->i_uid) ||
+	    likely(!(dir_mode & S_ISVTX)) ||
+	    uid_eq(inode->i_uid, dir_uid) ||
 	    uid_eq(current_fsuid(), inode->i_uid))
 		return 0;
 
-	if (likely(dir->d_inode->i_mode & 0002) ||
-	    (dir->d_inode->i_mode & 0020 &&
+	if (likely(dir_mode & 0002) ||
+	    (dir_mode & 0020 &&
 	     ((sysctl_protected_fifos >= 2 && S_ISFIFO(inode->i_mode)) ||
 	      (sysctl_protected_regular >= 2 && S_ISREG(inode->i_mode))))) {
 		const char *operation = S_ISFIFO(inode->i_mode) ?
@@ -3201,6 +3202,8 @@
 		   struct file *file, const struct open_flags *op)
 {
 	struct dentry *dir = nd->path.dentry;
+	kuid_t dir_uid = dir->d_inode->i_uid;
+	umode_t dir_mode = dir->d_inode->i_mode;
 	int open_flag = op->open_flag;
 	bool will_truncate = (open_flag & O_TRUNC) != 0;
 	bool got_write = false;
@@ -3331,7 +3334,7 @@
 		error = -EISDIR;
 		if (d_is_dir(nd->path.dentry))
 			goto out;
-		error = may_create_in_sticky(dir,
+		error = may_create_in_sticky(dir_mode, dir_uid,
 					     d_backing_inode(nd->path.dentry));
 		if (unlikely(error))
 			goto out;
```
