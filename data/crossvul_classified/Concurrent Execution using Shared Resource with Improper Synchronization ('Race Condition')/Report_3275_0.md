# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 3275_0
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3275_0`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 259-299 of the vulnerable file.

}

static void __d_free(struct rcu_head *head)
{
	struct dentry *dentry = container_of(head, struct dentry, d_u.d_rcu);

	kmem_cache_free(dentry_cache, dentry); 
}

static void __d_free_external(struct rcu_head *head)
{
	struct dentry *dentry = container_of(head, struct dentry, d_u.d_rcu);
	kfree(external_name(dentry));
	kmem_cache_free(dentry_cache, dentry); 
}

static inline int dname_external(const struct dentry *dentry)
{
	return dentry->d_name.name != dentry->d_iname;
}

static inline void __d_set_inode_and_type(struct dentry *dentry,
					  struct inode *inode,
					  unsigned type_flags)
{
	unsigned flags;

	dentry->d_inode = inode;
	flags = READ_ONCE(dentry->d_flags);
	flags &= ~(DCACHE_ENTRY_TYPE | DCACHE_FALLTHRU);
	flags |= type_flags;
	WRITE_ONCE(dentry->d_flags, flags);
}

static inline void __d_clear_type_and_inode(struct dentry *dentry)
{
	unsigned flags = READ_ONCE(dentry->d_flags);

	flags &= ~(DCACHE_ENTRY_TYPE | DCACHE_FALLTHRU);
	WRITE_ONCE(dentry->d_flags, flags);
	dentry->d_inode = NULL;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -276,6 +276,33 @@
 {
 	return dentry->d_name.name != dentry->d_iname;
 }
+
+void take_dentry_name_snapshot(struct name_snapshot *name, struct dentry *dentry)
+{
+	spin_lock(&dentry->d_lock);
+	if (unlikely(dname_external(dentry))) {
+		struct external_name *p = external_name(dentry);
+		atomic_inc(&p->u.count);
+		spin_unlock(&dentry->d_lock);
+		name->name = p->name;
+	} else {
+		memcpy(name->inline_name, dentry->d_iname, DNAME_INLINE_LEN);
+		spin_unlock(&dentry->d_lock);
+		name->name = name->inline_name;
+	}
+}
+EXPORT_SYMBOL(take_dentry_name_snapshot);
+
+void release_dentry_name_snapshot(struct name_snapshot *name)
+{
+	if (unlikely(name->name != name->inline_name)) {
+		struct external_name *p;
+		p = container_of(name->name, struct external_name, name[0]);
+		if (unlikely(atomic_dec_and_test(&p->u.count)))
+			kfree_rcu(p, u.head);
+	}
+}
+EXPORT_SYMBOL(release_dentry_name_snapshot);
 
 static inline void __d_set_inode_and_type(struct dentry *dentry,
 					  struct inode *inode,
```
