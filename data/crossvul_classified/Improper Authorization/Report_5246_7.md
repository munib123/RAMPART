# CrossVul Fix Pair: Improper Authorization in c
**Pair ID:** 5246_7
**Vulnerability Class:** Improper Authorization
**CWE:** CWE-285
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5246_7`)

## Vulnerability Information & PoC

## Description
Improper Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```c
Lines 48-89 of the vulnerable file.


	hfsplus_destroy_attr_entry((hfsplus_attr_entry *)value);

	return acl;
}

int hfsplus_set_posix_acl(struct inode *inode, struct posix_acl *acl,
		int type)
{
	int err;
	char *xattr_name;
	size_t size = 0;
	char *value = NULL;

	hfs_dbg(ACL_MOD, "[%s]: ino %lu\n", __func__, inode->i_ino);

	switch (type) {
	case ACL_TYPE_ACCESS:
		xattr_name = XATTR_NAME_POSIX_ACL_ACCESS;
		if (acl) {
			err = posix_acl_equiv_mode(acl, &inode->i_mode);
			if (err < 0)
				return err;
		}
		err = 0;
		break;

	case ACL_TYPE_DEFAULT:
		xattr_name = XATTR_NAME_POSIX_ACL_DEFAULT;
		if (!S_ISDIR(inode->i_mode))
			return acl ? -EACCES : 0;
		break;

	default:
		return -EINVAL;
	}

	if (acl) {
		size = posix_acl_xattr_size(acl->a_count);
		if (unlikely(size > HFSPLUS_MAX_INLINE_DATA_SIZE))
			return -ENOMEM;
		value = (char *)hfsplus_alloc_attr_entry();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -65,8 +65,8 @@
 	case ACL_TYPE_ACCESS:
 		xattr_name = XATTR_NAME_POSIX_ACL_ACCESS;
 		if (acl) {
-			err = posix_acl_equiv_mode(acl, &inode->i_mode);
-			if (err < 0)
+			err = posix_acl_update_mode(inode, &inode->i_mode, &acl);
+			if (err)
 				return err;
 		}
 		err = 0;
```
