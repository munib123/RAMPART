# CrossVul Fix Pair: Improper Authorization in c
**Pair ID:** 5246_1
**Vulnerability Class:** Improper Authorization
**CWE:** CWE-285
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5246_1`)

## Vulnerability Information & PoC

## Description
Improper Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```c
Lines 62-103 of the vulnerable file.

	}
	kfree(value);

	return acl;
}

/*
 * Needs to be called with fs_mutex held
 */
static int __btrfs_set_acl(struct btrfs_trans_handle *trans,
			 struct inode *inode, struct posix_acl *acl, int type)
{
	int ret, size = 0;
	const char *name;
	char *value = NULL;

	switch (type) {
	case ACL_TYPE_ACCESS:
		name = XATTR_NAME_POSIX_ACL_ACCESS;
		if (acl) {
			ret = posix_acl_equiv_mode(acl, &inode->i_mode);
			if (ret < 0)
				return ret;
			if (ret == 0)
				acl = NULL;
		}
		ret = 0;
		break;
	case ACL_TYPE_DEFAULT:
		if (!S_ISDIR(inode->i_mode))
			return acl ? -EINVAL : 0;
		name = XATTR_NAME_POSIX_ACL_DEFAULT;
		break;
	default:
		return -EINVAL;
	}

	if (acl) {
		size = posix_acl_xattr_size(acl->a_count);
		value = kmalloc(size, GFP_KERNEL);
		if (!value) {
			ret = -ENOMEM;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -79,11 +79,9 @@
 	case ACL_TYPE_ACCESS:
 		name = XATTR_NAME_POSIX_ACL_ACCESS;
 		if (acl) {
-			ret = posix_acl_equiv_mode(acl, &inode->i_mode);
-			if (ret < 0)
+			ret = posix_acl_update_mode(inode, &inode->i_mode, &acl);
+			if (ret)
 				return ret;
-			if (ret == 0)
-				acl = NULL;
 		}
 		ret = 0;
 		break;
```
