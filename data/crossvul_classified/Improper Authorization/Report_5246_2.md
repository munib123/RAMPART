# CrossVul Fix Pair: Improper Authorization in c
**Pair ID:** 5246_2
**Vulnerability Class:** Improper Authorization
**CWE:** CWE-285
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5246_2`)

## Vulnerability Information & PoC

## Description
Improper Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```c
Lines 78-119 of the vulnerable file.

	kfree(value);

	if (!IS_ERR(acl))
		ceph_set_cached_acl(inode, type, acl);

	return acl;
}

int ceph_set_acl(struct inode *inode, struct posix_acl *acl, int type)
{
	int ret = 0, size = 0;
	const char *name = NULL;
	char *value = NULL;
	struct iattr newattrs;
	umode_t new_mode = inode->i_mode, old_mode = inode->i_mode;

	switch (type) {
	case ACL_TYPE_ACCESS:
		name = XATTR_NAME_POSIX_ACL_ACCESS;
		if (acl) {
			ret = posix_acl_equiv_mode(acl, &new_mode);
			if (ret < 0)
				goto out;
			if (ret == 0)
				acl = NULL;
		}
		break;
	case ACL_TYPE_DEFAULT:
		if (!S_ISDIR(inode->i_mode)) {
			ret = acl ? -EINVAL : 0;
			goto out;
		}
		name = XATTR_NAME_POSIX_ACL_DEFAULT;
		break;
	default:
		ret = -EINVAL;
		goto out;
	}

	if (acl) {
		size = posix_acl_xattr_size(acl->a_count);
		value = kmalloc(size, GFP_NOFS);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -95,11 +95,9 @@
 	case ACL_TYPE_ACCESS:
 		name = XATTR_NAME_POSIX_ACL_ACCESS;
 		if (acl) {
-			ret = posix_acl_equiv_mode(acl, &new_mode);
-			if (ret < 0)
+			ret = posix_acl_update_mode(inode, &new_mode, &acl);
+			if (ret)
 				goto out;
-			if (ret == 0)
-				acl = NULL;
 		}
 		break;
 	case ACL_TYPE_DEFAULT:
```
