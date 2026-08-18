# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 2190_5
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2190_5`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 407-446 of the vulnerable file.

}
EXPORT_SYMBOL(file_ns_capable);

/**
 * capable - Determine if the current task has a superior capability in effect
 * @cap: The capability to be tested for
 *
 * Return true if the current task has the given superior capability currently
 * available for use, false if not.
 *
 * This sets PF_SUPERPRIV on the task if the capability is available on the
 * assumption that it's about to be used.
 */
bool capable(int cap)
{
	return ns_capable(&init_user_ns, cap);
}
EXPORT_SYMBOL(capable);

/**
 * inode_capable - Check superior capability over inode
 * @inode: The inode in question
 * @cap: The capability in question
 *
 * Return true if the current task has the given superior capability
 * targeted at it's own user namespace and that the given inode is owned
 * by the current user namespace or a child namespace.
 *
 * Currently we check to see if an inode is owned by the current
 * user namespace by seeing if the inode's owner maps into the
 * current user namespace.
 *
 */
bool inode_capable(const struct inode *inode, int cap)
{
	struct user_namespace *ns = current_user_ns();

	return ns_capable(ns, cap) && kuid_has_mapping(ns, inode->i_uid);
}
EXPORT_SYMBOL(inode_capable);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -424,23 +424,19 @@
 EXPORT_SYMBOL(capable);
 
 /**
- * inode_capable - Check superior capability over inode
+ * capable_wrt_inode_uidgid - Check nsown_capable and uid and gid mapped
  * @inode: The inode in question
  * @cap: The capability in question
  *
- * Return true if the current task has the given superior capability
- * targeted at it's own user namespace and that the given inode is owned
- * by the current user namespace or a child namespace.
- *
- * Currently we check to see if an inode is owned by the current
- * user namespace by seeing if the inode's owner maps into the
- * current user namespace.
- *
- */
-bool inode_capable(const struct inode *inode, int cap)
+ * Return true if the current task has the given capability targeted at
+ * its own user namespace and that the given inode's uid and gid are
+ * mapped into the current user namespace.
+ */
+bool capable_wrt_inode_uidgid(const struct inode *inode, int cap)
 {
 	struct user_namespace *ns = current_user_ns();
 
-	return ns_capable(ns, cap) && kuid_has_mapping(ns, inode->i_uid);
-}
-EXPORT_SYMBOL(inode_capable);
+	return ns_capable(ns, cap) && kuid_has_mapping(ns, inode->i_uid) &&
+		kgid_has_mapping(ns, inode->i_gid);
+}
+EXPORT_SYMBOL(capable_wrt_inode_uidgid);
```
