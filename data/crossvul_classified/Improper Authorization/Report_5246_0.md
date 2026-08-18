# CrossVul Fix Pair: Improper Authorization in c
**Pair ID:** 5246_0
**Vulnerability Class:** Improper Authorization
**CWE:** CWE-285
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5246_0`)

## Vulnerability Information & PoC

## Description
Improper Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```c
Lines 259-301 of the vulnerable file.

	if (S_ISLNK(inode->i_mode))
		return -EOPNOTSUPP;
	if (!inode_owner_or_capable(inode))
		return -EPERM;
	if (value) {
		/* update the cached acl value */
		acl = posix_acl_from_xattr(&init_user_ns, value, size);
		if (IS_ERR(acl))
			return PTR_ERR(acl);
		else if (acl) {
			retval = posix_acl_valid(inode->i_sb->s_user_ns, acl);
			if (retval)
				goto err_out;
		}
	} else
		acl = NULL;

	switch (handler->flags) {
	case ACL_TYPE_ACCESS:
		if (acl) {
			umode_t mode = inode->i_mode;
			retval = posix_acl_equiv_mode(acl, &mode);
			if (retval < 0)
				goto err_out;
			else {
				struct iattr iattr;
				if (retval == 0) {
					/*
					 * ACL can be represented
					 * by the mode bits. So don't
					 * update ACL.
					 */
					acl = NULL;
					value = NULL;
					size = 0;
				}
				/* Updte the mode bits */
				iattr.ia_mode = ((mode & S_IALLUGO) |
						 (inode->i_mode & ~S_IALLUGO));
				iattr.ia_valid = ATTR_MODE;
				/* FIXME should we update ctime ?
				 * What is the following setxattr update the
				 * mode ?
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -276,32 +276,26 @@
 	switch (handler->flags) {
 	case ACL_TYPE_ACCESS:
 		if (acl) {
-			umode_t mode = inode->i_mode;
-			retval = posix_acl_equiv_mode(acl, &mode);
-			if (retval < 0)
+			struct iattr iattr;
+
+			retval = posix_acl_update_mode(inode, &iattr.ia_mode, &acl);
+			if (retval)
 				goto err_out;
-			else {
-				struct iattr iattr;
-				if (retval == 0) {
-					/*
-					 * ACL can be represented
-					 * by the mode bits. So don't
-					 * update ACL.
-					 */
-					acl = NULL;
-					value = NULL;
-					size = 0;
-				}
-				/* Updte the mode bits */
-				iattr.ia_mode = ((mode & S_IALLUGO) |
-						 (inode->i_mode & ~S_IALLUGO));
-				iattr.ia_valid = ATTR_MODE;
-				/* FIXME should we update ctime ?
-				 * What is the following setxattr update the
-				 * mode ?
+			if (!acl) {
+				/*
+				 * ACL can be represented
+				 * by the mode bits. So don't
+				 * update ACL.
 				 */
-				v9fs_vfs_setattr_dotl(dentry, &iattr);
+				value = NULL;
+				size = 0;
 			}
+			iattr.ia_valid = ATTR_MODE;
+			/* FIXME should we update ctime ?
+			 * What is the following setxattr update the
+			 * mode ?
+			 */
+			v9fs_vfs_setattr_dotl(dentry, &iattr);
 		}
 		break;
 	case ACL_TYPE_DEFAULT:
```
