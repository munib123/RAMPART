# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 3275_4
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3275_4`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 574-595 of the vulnerable file.

{
	if (unlikely(dentry->d_flags & DCACHE_OP_REAL))
		return dentry->d_op->d_real(dentry, inode, flags);
	else
		return dentry;
}

/**
 * d_real_inode - Return the real inode
 * @dentry: The dentry to query
 *
 * If dentry is on a union/overlay, then return the underlying, real inode.
 * Otherwise return d_inode().
 */
static inline struct inode *d_real_inode(const struct dentry *dentry)
{
	/* This usage of d_real() results in const dentry */
	return d_backing_inode(d_real((struct dentry *) dentry, NULL, 0));
}


#endif	/* __LINUX_DCACHE_H */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -591,5 +591,11 @@
 	return d_backing_inode(d_real((struct dentry *) dentry, NULL, 0));
 }
 
+struct name_snapshot {
+	const char *name;
+	char inline_name[DNAME_INLINE_LEN];
+};
+void take_dentry_name_snapshot(struct name_snapshot *, struct dentry *);
+void release_dentry_name_snapshot(struct name_snapshot *);
 
 #endif	/* __LINUX_DCACHE_H */
```
