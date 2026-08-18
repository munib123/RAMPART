# CrossVul Fix Pair: Improper Access Control in c
**Pair ID:** 5198_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5198_0`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```c
Lines 823-864 of the vulnerable file.

	file->f_path.dentry = dentry;
	return 1;
}
EXPORT_SYMBOL(finish_no_open);

char *file_path(struct file *filp, char *buf, int buflen)
{
	return d_path(&filp->f_path, buf, buflen);
}
EXPORT_SYMBOL(file_path);

/**
 * vfs_open - open the file at the given path
 * @path: path to open
 * @file: newly allocated file with f_flag initialized
 * @cred: credentials to use
 */
int vfs_open(const struct path *path, struct file *file,
	     const struct cred *cred)
{
	struct dentry *dentry = path->dentry;
	struct inode *inode = dentry->d_inode;

	file->f_path = *path;
	if (dentry->d_flags & DCACHE_OP_SELECT_INODE) {
		inode = dentry->d_op->d_select_inode(dentry, file->f_flags);
		if (IS_ERR(inode))
			return PTR_ERR(inode);
	}

	return do_dentry_open(file, inode, NULL, cred);
}

struct file *dentry_open(const struct path *path, int flags,
			 const struct cred *cred)
{
	int error;
	struct file *f;

	validate_creds(cred);

	/* We must always pass in a valid mount pointer. */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -840,16 +840,12 @@
 int vfs_open(const struct path *path, struct file *file,
 	     const struct cred *cred)
 {
-	struct dentry *dentry = path->dentry;
-	struct inode *inode = dentry->d_inode;
+	struct inode *inode = vfs_select_inode(path->dentry, file->f_flags);
+
+	if (IS_ERR(inode))
+		return PTR_ERR(inode);
 
 	file->f_path = *path;
-	if (dentry->d_flags & DCACHE_OP_SELECT_INODE) {
-		inode = dentry->d_op->d_select_inode(dentry, file->f_flags);
-		if (IS_ERR(inode))
-			return PTR_ERR(inode);
-	}
-
 	return do_dentry_open(file, inode, NULL, cred);
 }
 
```
