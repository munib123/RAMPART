# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 3275_2
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3275_2`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 4345-4385 of the vulnerable file.

 *	   only under ->s_vfs_rename_mutex _and_ that parent of the object we
 *	   move will be locked.  Thus we can rank directories by the tree
 *	   (ancestors first) and rank all non-directories after them.
 *	   That works since everybody except rename does "lock parent, lookup,
 *	   lock child" and rename is under ->s_vfs_rename_mutex.
 *	   HOWEVER, it relies on the assumption that any object with ->lookup()
 *	   has no more than 1 dentry.  If "hybrid" objects will ever appear,
 *	   we'd better make sure that there's no link(2) for them.
 *	d) conversion from fhandle to dentry may come in the wrong moment - when
 *	   we are removing the target. Solution: we will have to grab ->i_mutex
 *	   in the fhandle_to_dentry code. [FIXME - current nfsfh.c relies on
 *	   ->i_mutex on parents, which works but leads to some truly excessive
 *	   locking].
 */
int vfs_rename(struct inode *old_dir, struct dentry *old_dentry,
	       struct inode *new_dir, struct dentry *new_dentry,
	       struct inode **delegated_inode, unsigned int flags)
{
	int error;
	bool is_dir = d_is_dir(old_dentry);
	const unsigned char *old_name;
	struct inode *source = old_dentry->d_inode;
	struct inode *target = new_dentry->d_inode;
	bool new_is_dir = false;
	unsigned max_links = new_dir->i_sb->s_max_links;

	if (source == target)
		return 0;

	error = may_delete(old_dir, old_dentry, is_dir);
	if (error)
		return error;

	if (!target) {
		error = may_create(new_dir, new_dentry);
	} else {
		new_is_dir = d_is_dir(new_dentry);

		if (!(flags & RENAME_EXCHANGE))
			error = may_delete(new_dir, new_dentry, is_dir);
		else
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4362,11 +4362,11 @@
 {
 	int error;
 	bool is_dir = d_is_dir(old_dentry);
-	const unsigned char *old_name;
 	struct inode *source = old_dentry->d_inode;
 	struct inode *target = new_dentry->d_inode;
 	bool new_is_dir = false;
 	unsigned max_links = new_dir->i_sb->s_max_links;
+	struct name_snapshot old_name;
 
 	if (source == target)
 		return 0;
@@ -4413,7 +4413,7 @@
 	if (error)
 		return error;
 
-	old_name = fsnotify_oldname_init(old_dentry->d_name.name);
+	take_dentry_name_snapshot(&old_name, old_dentry);
 	dget(new_dentry);
 	if (!is_dir || (flags & RENAME_EXCHANGE))
 		lock_two_nondirectories(source, target);
@@ -4468,14 +4468,14 @@
 		inode_unlock(target);
 	dput(new_dentry);
 	if (!error) {
-		fsnotify_move(old_dir, new_dir, old_name, is_dir,
+		fsnotify_move(old_dir, new_dir, old_name.name, is_dir,
 			      !(flags & RENAME_EXCHANGE) ? target : NULL, old_dentry);
 		if (flags & RENAME_EXCHANGE) {
 			fsnotify_move(new_dir, old_dir, old_dentry->d_name.name,
 				      new_is_dir, NULL, new_dentry);
 		}
 	}
-	fsnotify_oldname_free(old_name);
+	release_dentry_name_snapshot(&old_name);
 
 	return error;
 }
```
