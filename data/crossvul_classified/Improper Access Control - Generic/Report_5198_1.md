# CrossVul Fix Pair: Improper Access Control in c
**Pair ID:** 5198_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5198_1`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```c
Lines 548-568 of the vulnerable file.

 *
 * This is the helper that should be used to get the dentry of the inode that
 * will be used if this dentry were opened as a file.  It may be the upper
 * dentry or it may be a lower dentry pinned by the upper.
 *
 * Normal filesystems should not use this to access their own dentries.
 */
static inline struct dentry *d_backing_dentry(struct dentry *upper)
{
	return upper;
}

static inline struct dentry *d_real(struct dentry *dentry)
{
	if (unlikely(dentry->d_flags & DCACHE_OP_REAL))
		return dentry->d_op->d_real(dentry, NULL);
	else
		return dentry;
}

#endif	/* __LINUX_DCACHE_H */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -565,4 +565,16 @@
 		return dentry;
 }
 
+static inline struct inode *vfs_select_inode(struct dentry *dentry,
+					     unsigned open_flags)
+{
+	struct inode *inode = d_inode(dentry);
+
+	if (inode && unlikely(dentry->d_flags & DCACHE_OP_SELECT_INODE))
+		inode = dentry->d_op->d_select_inode(dentry, open_flags);
+
+	return inode;
+}
+
+
 #endif	/* __LINUX_DCACHE_H */
```
