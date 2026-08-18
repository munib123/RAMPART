# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 2190_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2190_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 33-73 of the vulnerable file.

	unsigned int ia_valid = attr->ia_valid;

	/*
	 * First check size constraints.  These can't be overriden using
	 * ATTR_FORCE.
	 */
	if (ia_valid & ATTR_SIZE) {
		int error = inode_newsize_ok(inode, attr->ia_size);
		if (error)
			return error;
	}

	/* If force is set do it anyway. */
	if (ia_valid & ATTR_FORCE)
		return 0;

	/* Make sure a caller can chown. */
	if ((ia_valid & ATTR_UID) &&
	    (!uid_eq(current_fsuid(), inode->i_uid) ||
	     !uid_eq(attr->ia_uid, inode->i_uid)) &&
	    !inode_capable(inode, CAP_CHOWN))
		return -EPERM;

	/* Make sure caller can chgrp. */
	if ((ia_valid & ATTR_GID) &&
	    (!uid_eq(current_fsuid(), inode->i_uid) ||
	    (!in_group_p(attr->ia_gid) && !gid_eq(attr->ia_gid, inode->i_gid))) &&
	    !inode_capable(inode, CAP_CHOWN))
		return -EPERM;

	/* Make sure a caller can chmod. */
	if (ia_valid & ATTR_MODE) {
		if (!inode_owner_or_capable(inode))
			return -EPERM;
		/* Also check the setgid bit! */
		if (!in_group_p((ia_valid & ATTR_GID) ? attr->ia_gid :
				inode->i_gid) &&
		    !inode_capable(inode, CAP_FSETID))
			attr->ia_mode &= ~S_ISGID;
	}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -50,14 +50,14 @@
 	if ((ia_valid & ATTR_UID) &&
 	    (!uid_eq(current_fsuid(), inode->i_uid) ||
 	     !uid_eq(attr->ia_uid, inode->i_uid)) &&
-	    !inode_capable(inode, CAP_CHOWN))
+	    !capable_wrt_inode_uidgid(inode, CAP_CHOWN))
 		return -EPERM;
 
 	/* Make sure caller can chgrp. */
 	if ((ia_valid & ATTR_GID) &&
 	    (!uid_eq(current_fsuid(), inode->i_uid) ||
 	    (!in_group_p(attr->ia_gid) && !gid_eq(attr->ia_gid, inode->i_gid))) &&
-	    !inode_capable(inode, CAP_CHOWN))
+	    !capable_wrt_inode_uidgid(inode, CAP_CHOWN))
 		return -EPERM;
 
 	/* Make sure a caller can chmod. */
@@ -67,7 +67,7 @@
 		/* Also check the setgid bit! */
 		if (!in_group_p((ia_valid & ATTR_GID) ? attr->ia_gid :
 				inode->i_gid) &&
-		    !inode_capable(inode, CAP_FSETID))
+		    !capable_wrt_inode_uidgid(inode, CAP_FSETID))
 			attr->ia_mode &= ~S_ISGID;
 	}
 
@@ -160,7 +160,7 @@
 		umode_t mode = attr->ia_mode;
 
 		if (!in_group_p(inode->i_gid) &&
-		    !inode_capable(inode, CAP_FSETID))
+		    !capable_wrt_inode_uidgid(inode, CAP_FSETID))
 			mode &= ~S_ISGID;
 		inode->i_mode = mode;
 	}
```
