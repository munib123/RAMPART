# CrossVul Fix Pair: Incorrect Permission Assignment for Critical Resource in c
**Pair ID:** 4284_4
**Vulnerability Class:** Incorrect Permission Assignment for Critical Resource
**CWE:** CWE-732
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4284_4`)

## Vulnerability Information & PoC

## Description
Incorrect Permission Assignment for Critical Resource - When a resource is given a permission setting that provides access to a wider range of actors than required, it could lead to the exposure of sensitive information, or the modification of that reso...

## Vulnerable Code
```c
Lines 2288-2329 of the vulnerable file.


	return (zfs_zaccess_common(zp, ACE_APPEND_DATA, working_mode,
	    check_privs, B_FALSE, cr));
}

/*
 * Check if VEXEC is allowed.
 *
 * This routine is based on zfs_fastaccesschk_execute which has slowpath
 * calling zfs_zaccess. This would be incorrect on FreeBSD (see
 * zfs_freebsd_access for the difference). Thus this variant let's the
 * caller handle the slowpath (if necessary).
 *
 * On top of that we perform a lockless check for ZFS_NO_EXECS_DENIED.
 *
 * Safe access to znode_t is provided by the vnode lock.
 */
int
zfs_fastaccesschk_execute(znode_t *zdp, cred_t *cr)
{
	boolean_t owner = B_FALSE;
	boolean_t groupmbr = B_FALSE;
	boolean_t is_attr;
	uid_t uid = crgetuid(cr);

	if (zdp->z_pflags & ZFS_AV_QUARANTINED)
		return (1);

	is_attr = ((zdp->z_pflags & ZFS_XATTR) &&
	    (ZTOV(zdp)->v_type == VDIR));
	if (is_attr)
		return (1);

	if (zdp->z_pflags & ZFS_NO_EXECS_DENIED)
		return (0);

	mutex_enter(&zdp->z_acl_lock);
	if (FUID_INDEX(zdp->z_uid) != 0 || FUID_INDEX(zdp->z_gid) != 0) {
		goto out_slow;
	}

	if (uid == zdp->z_uid) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2305,10 +2305,7 @@
 int
 zfs_fastaccesschk_execute(znode_t *zdp, cred_t *cr)
 {
-	boolean_t owner = B_FALSE;
-	boolean_t groupmbr = B_FALSE;
 	boolean_t is_attr;
-	uid_t uid = crgetuid(cr);
 
 	if (zdp->z_pflags & ZFS_AV_QUARANTINED)
 		return (1);
@@ -2321,37 +2318,6 @@
 	if (zdp->z_pflags & ZFS_NO_EXECS_DENIED)
 		return (0);
 
-	mutex_enter(&zdp->z_acl_lock);
-	if (FUID_INDEX(zdp->z_uid) != 0 || FUID_INDEX(zdp->z_gid) != 0) {
-		goto out_slow;
-	}
-
-	if (uid == zdp->z_uid) {
-		owner = B_TRUE;
-		if (zdp->z_mode & S_IXUSR) {
-			goto out;
-		} else {
-			goto out_slow;
-		}
-	}
-	if (groupmember(zdp->z_gid, cr)) {
-		groupmbr = B_TRUE;
-		if (zdp->z_mode & S_IXGRP) {
-			goto out;
-		} else {
-			goto out_slow;
-		}
-	}
-	if (!owner && !groupmbr) {
-		if (zdp->z_mode & S_IXOTH) {
-			goto out;
-		}
-	}
-out:
-	mutex_exit(&zdp->z_acl_lock);
-	return (0);
-out_slow:
-	mutex_exit(&zdp->z_acl_lock);
 	return (1);
 }
 
```
