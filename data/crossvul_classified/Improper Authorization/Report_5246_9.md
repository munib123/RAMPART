# CrossVul Fix Pair: Improper Authorization in c
**Pair ID:** 5246_9
**Vulnerability Class:** Improper Authorization
**CWE:** CWE-285
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5246_9`)

## Vulnerability Information & PoC

## Description
Improper Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```c
Lines 61-102 of the vulnerable file.

			acl = ERR_PTR(size);
	} else {
		acl = posix_acl_from_xattr(&init_user_ns, value, size);
	}
	kfree(value);
	return acl;
}

static int __jfs_set_acl(tid_t tid, struct inode *inode, int type,
		       struct posix_acl *acl)
{
	char *ea_name;
	int rc;
	int size = 0;
	char *value = NULL;

	switch (type) {
	case ACL_TYPE_ACCESS:
		ea_name = XATTR_NAME_POSIX_ACL_ACCESS;
		if (acl) {
			rc = posix_acl_equiv_mode(acl, &inode->i_mode);
			if (rc < 0)
				return rc;
			inode->i_ctime = CURRENT_TIME;
			mark_inode_dirty(inode);
			if (rc == 0)
				acl = NULL;
		}
		break;
	case ACL_TYPE_DEFAULT:
		ea_name = XATTR_NAME_POSIX_ACL_DEFAULT;
		break;
	default:
		return -EINVAL;
	}

	if (acl) {
		size = posix_acl_xattr_size(acl->a_count);
		value = kmalloc(size, GFP_KERNEL);
		if (!value)
			return -ENOMEM;
		rc = posix_acl_to_xattr(&init_user_ns, acl, value, size);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -78,13 +78,11 @@
 	case ACL_TYPE_ACCESS:
 		ea_name = XATTR_NAME_POSIX_ACL_ACCESS;
 		if (acl) {
-			rc = posix_acl_equiv_mode(acl, &inode->i_mode);
-			if (rc < 0)
+			rc = posix_acl_update_mode(inode, &inode->i_mode, &acl);
+			if (rc)
 				return rc;
 			inode->i_ctime = CURRENT_TIME;
 			mark_inode_dirty(inode);
-			if (rc == 0)
-				acl = NULL;
 		}
 		break;
 	case ACL_TYPE_DEFAULT:
```
