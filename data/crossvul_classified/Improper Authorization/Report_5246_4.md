# CrossVul Fix Pair: Improper Authorization in c
**Pair ID:** 5246_4
**Vulnerability Class:** Improper Authorization
**CWE:** CWE-285
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5246_4`)

## Vulnerability Information & PoC

## Description
Improper Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```c
Lines 176-217 of the vulnerable file.

}

/*
 * Set the access or default ACL of an inode.
 *
 * inode->i_mutex: down unless called from ext4_new_inode
 */
static int
__ext4_set_acl(handle_t *handle, struct inode *inode, int type,
	     struct posix_acl *acl)
{
	int name_index;
	void *value = NULL;
	size_t size = 0;
	int error;

	switch (type) {
	case ACL_TYPE_ACCESS:
		name_index = EXT4_XATTR_INDEX_POSIX_ACL_ACCESS;
		if (acl) {
			error = posix_acl_equiv_mode(acl, &inode->i_mode);
			if (error < 0)
				return error;
			else {
				inode->i_ctime = ext4_current_time(inode);
				ext4_mark_inode_dirty(handle, inode);
				if (error == 0)
					acl = NULL;
			}
		}
		break;

	case ACL_TYPE_DEFAULT:
		name_index = EXT4_XATTR_INDEX_POSIX_ACL_DEFAULT;
		if (!S_ISDIR(inode->i_mode))
			return acl ? -EACCES : 0;
		break;

	default:
		return -EINVAL;
	}
	if (acl) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -193,15 +193,11 @@
 	case ACL_TYPE_ACCESS:
 		name_index = EXT4_XATTR_INDEX_POSIX_ACL_ACCESS;
 		if (acl) {
-			error = posix_acl_equiv_mode(acl, &inode->i_mode);
-			if (error < 0)
+			error = posix_acl_update_mode(inode, &inode->i_mode, &acl);
+			if (error)
 				return error;
-			else {
-				inode->i_ctime = ext4_current_time(inode);
-				ext4_mark_inode_dirty(handle, inode);
-				if (error == 0)
-					acl = NULL;
-			}
+			inode->i_ctime = ext4_current_time(inode);
+			ext4_mark_inode_dirty(handle, inode);
 		}
 		break;
 
```
