# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 2190_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2190_1`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 1822-1863 of the vulnerable file.

 * @mode: mode of the new inode
 */
void inode_init_owner(struct inode *inode, const struct inode *dir,
			umode_t mode)
{
	inode->i_uid = current_fsuid();
	if (dir && dir->i_mode & S_ISGID) {
		inode->i_gid = dir->i_gid;
		if (S_ISDIR(mode))
			mode |= S_ISGID;
	} else
		inode->i_gid = current_fsgid();
	inode->i_mode = mode;
}
EXPORT_SYMBOL(inode_init_owner);

/**
 * inode_owner_or_capable - check current task permissions to inode
 * @inode: inode being checked
 *
 * Return true if current either has CAP_FOWNER to the inode, or
 * owns the file.
 */
bool inode_owner_or_capable(const struct inode *inode)
{
	if (uid_eq(current_fsuid(), inode->i_uid))
		return true;
	if (inode_capable(inode, CAP_FOWNER))
		return true;
	return false;
}
EXPORT_SYMBOL(inode_owner_or_capable);

/*
 * Direct i/o helper functions
 */
static void __inode_dio_wait(struct inode *inode)
{
	wait_queue_head_t *wq = bit_waitqueue(&inode->i_state, __I_DIO_WAKEUP);
	DEFINE_WAIT_BIT(q, &inode->i_state, __I_DIO_WAKEUP);

	do {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1839,14 +1839,18 @@
  * inode_owner_or_capable - check current task permissions to inode
  * @inode: inode being checked
  *
- * Return true if current either has CAP_FOWNER to the inode, or
- * owns the file.
+ * Return true if current either has CAP_FOWNER in a namespace with the
+ * inode owner uid mapped, or owns the file.
  */
 bool inode_owner_or_capable(const struct inode *inode)
 {
+	struct user_namespace *ns;
+
 	if (uid_eq(current_fsuid(), inode->i_uid))
 		return true;
-	if (inode_capable(inode, CAP_FOWNER))
+
+	ns = current_user_ns();
+	if (ns_capable(ns, CAP_FOWNER) && kuid_has_mapping(ns, inode->i_uid))
 		return true;
 	return false;
 }
```
