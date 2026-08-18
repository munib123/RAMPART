# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 3275_1
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3275_1`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 749-789 of the vulnerable file.

 * @old_dentry: dentry of an object to be renamed.
 * @new_dir: a pointer to the parent dentry where the object should be
 *          moved. This should be a directory dentry.
 * @new_name: a pointer to a string containing the target name.
 *
 * This function renames a file/directory in debugfs.  The target must not
 * exist for rename to succeed.
 *
 * This function will return a pointer to old_dentry (which is updated to
 * reflect renaming) if it succeeds. If an error occurs, %NULL will be
 * returned.
 *
 * If debugfs is not enabled in the kernel, the value -%ENODEV will be
 * returned.
 */
struct dentry *debugfs_rename(struct dentry *old_dir, struct dentry *old_dentry,
		struct dentry *new_dir, const char *new_name)
{
	int error;
	struct dentry *dentry = NULL, *trap;
	const char *old_name;

	trap = lock_rename(new_dir, old_dir);
	/* Source or destination directories don't exist? */
	if (d_really_is_negative(old_dir) || d_really_is_negative(new_dir))
		goto exit;
	/* Source does not exist, cyclic rename, or mountpoint? */
	if (d_really_is_negative(old_dentry) || old_dentry == trap ||
	    d_mountpoint(old_dentry))
		goto exit;
	dentry = lookup_one_len(new_name, new_dir, strlen(new_name));
	/* Lookup failed, cyclic rename or target exists? */
	if (IS_ERR(dentry) || dentry == trap || d_really_is_positive(dentry))
		goto exit;

	old_name = fsnotify_oldname_init(old_dentry->d_name.name);

	error = simple_rename(d_inode(old_dir), old_dentry, d_inode(new_dir),
			      dentry, 0);
	if (error) {
		fsnotify_oldname_free(old_name);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -766,7 +766,7 @@
 {
 	int error;
 	struct dentry *dentry = NULL, *trap;
-	const char *old_name;
+	struct name_snapshot old_name;
 
 	trap = lock_rename(new_dir, old_dir);
 	/* Source or destination directories don't exist? */
@@ -781,19 +781,19 @@
 	if (IS_ERR(dentry) || dentry == trap || d_really_is_positive(dentry))
 		goto exit;
 
-	old_name = fsnotify_oldname_init(old_dentry->d_name.name);
+	take_dentry_name_snapshot(&old_name, old_dentry);
 
 	error = simple_rename(d_inode(old_dir), old_dentry, d_inode(new_dir),
 			      dentry, 0);
 	if (error) {
-		fsnotify_oldname_free(old_name);
+		release_dentry_name_snapshot(&old_name);
 		goto exit;
 	}
 	d_move(old_dentry, dentry);
-	fsnotify_move(d_inode(old_dir), d_inode(new_dir), old_name,
+	fsnotify_move(d_inode(old_dir), d_inode(new_dir), old_name.name,
 		d_is_dir(old_dentry),
 		NULL, old_dentry);
-	fsnotify_oldname_free(old_name);
+	release_dentry_name_snapshot(&old_name);
 	unlock_rename(new_dir, old_dir);
 	dput(dentry);
 	return old_dentry;
```
