# CrossVul Fix Pair: Improper Authorization in c
**Pair ID:** 5246_8
**Vulnerability Class:** Improper Authorization
**CWE:** CWE-285
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5246_8`)

## Vulnerability Information & PoC

## Description
Improper Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```c
Lines 216-258 of the vulnerable file.

		value = jffs2_acl_to_medium(acl, &size);
		if (IS_ERR(value))
			return PTR_ERR(value);
	}
	rc = do_jffs2_setxattr(inode, xprefix, "", value, size, 0);
	if (!value && rc == -ENODATA)
		rc = 0;
	kfree(value);

	return rc;
}

int jffs2_set_acl(struct inode *inode, struct posix_acl *acl, int type)
{
	int rc, xprefix;

	switch (type) {
	case ACL_TYPE_ACCESS:
		xprefix = JFFS2_XPREFIX_ACL_ACCESS;
		if (acl) {
			umode_t mode = inode->i_mode;
			rc = posix_acl_equiv_mode(acl, &mode);
			if (rc < 0)
				return rc;
			if (inode->i_mode != mode) {
				struct iattr attr;

				attr.ia_valid = ATTR_MODE | ATTR_CTIME;
				attr.ia_mode = mode;
				attr.ia_ctime = CURRENT_TIME_SEC;
				rc = jffs2_do_setattr(inode, &attr);
				if (rc < 0)
					return rc;
			}
			if (rc == 0)
				acl = NULL;
		}
		break;
	case ACL_TYPE_DEFAULT:
		xprefix = JFFS2_XPREFIX_ACL_DEFAULT;
		if (!S_ISDIR(inode->i_mode))
			return acl ? -EACCES : 0;
		break;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -233,9 +233,10 @@
 	case ACL_TYPE_ACCESS:
 		xprefix = JFFS2_XPREFIX_ACL_ACCESS;
 		if (acl) {
-			umode_t mode = inode->i_mode;
-			rc = posix_acl_equiv_mode(acl, &mode);
-			if (rc < 0)
+			umode_t mode;
+
+			rc = posix_acl_update_mode(inode, &mode, &acl);
+			if (rc)
 				return rc;
 			if (inode->i_mode != mode) {
 				struct iattr attr;
@@ -247,8 +248,6 @@
 				if (rc < 0)
 					return rc;
 			}
-			if (rc == 0)
-				acl = NULL;
 		}
 		break;
 	case ACL_TYPE_DEFAULT:
```
