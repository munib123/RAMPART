# CrossVul Fix Pair: Improper Authorization in c
**Pair ID:** 5246_6
**Vulnerability Class:** Improper Authorization
**CWE:** CWE-285
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5246_6`)

## Vulnerability Information & PoC

## Description
Improper Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```c
Lines 75-116 of the vulnerable file.

	}
	acl = __gfs2_get_acl(inode, type);
	if (need_unlock)
		gfs2_glock_dq_uninit(&gh);
	return acl;
}

int __gfs2_set_acl(struct inode *inode, struct posix_acl *acl, int type)
{
	int error;
	int len;
	char *data;
	const char *name = gfs2_acl_name(type);

	if (acl && acl->a_count > GFS2_ACL_MAX_ENTRIES(GFS2_SB(inode)))
		return -E2BIG;

	if (type == ACL_TYPE_ACCESS) {
		umode_t mode = inode->i_mode;

		error = posix_acl_equiv_mode(acl, &mode);
		if (error < 0)
			return error;

		if (error == 0)
			acl = NULL;

		if (mode != inode->i_mode) {
			inode->i_mode = mode;
			mark_inode_dirty(inode);
		}
	}

	if (acl) {
		len = posix_acl_to_xattr(&init_user_ns, acl, NULL, 0);
		if (len == 0)
			return 0;
		data = kmalloc(len, GFP_NOFS);
		if (data == NULL)
			return -ENOMEM;
		error = posix_acl_to_xattr(&init_user_ns, acl, data, len);
		if (error < 0)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -92,17 +92,11 @@
 	if (type == ACL_TYPE_ACCESS) {
 		umode_t mode = inode->i_mode;
 
-		error = posix_acl_equiv_mode(acl, &mode);
-		if (error < 0)
+		error = posix_acl_update_mode(inode, &inode->i_mode, &acl);
+		if (error)
 			return error;
-
-		if (error == 0)
-			acl = NULL;
-
-		if (mode != inode->i_mode) {
-			inode->i_mode = mode;
+		if (mode != inode->i_mode)
 			mark_inode_dirty(inode);
-		}
 	}
 
 	if (acl) {
```
