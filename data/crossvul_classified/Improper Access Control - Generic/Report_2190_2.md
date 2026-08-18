# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 2190_2
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2190_2`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 315-355 of the vulnerable file.

 * for filesystem access without changing the "normal" uids which
 * are used for other things.
 *
 * generic_permission is rcu-walk aware. It returns -ECHILD in case an rcu-walk
 * request cannot be satisfied (eg. requires blocking or too much complexity).
 * It would then be called again in ref-walk mode.
 */
int generic_permission(struct inode *inode, int mask)
{
	int ret;

	/*
	 * Do the basic permission checks.
	 */
	ret = acl_permission_check(inode, mask);
	if (ret != -EACCES)
		return ret;

	if (S_ISDIR(inode->i_mode)) {
		/* DACs are overridable for directories */
		if (inode_capable(inode, CAP_DAC_OVERRIDE))
			return 0;
		if (!(mask & MAY_WRITE))
			if (inode_capable(inode, CAP_DAC_READ_SEARCH))
				return 0;
		return -EACCES;
	}
	/*
	 * Read/write DACs are always overridable.
	 * Executable DACs are overridable when there is
	 * at least one exec bit set.
	 */
	if (!(mask & MAY_EXEC) || (inode->i_mode & S_IXUGO))
		if (inode_capable(inode, CAP_DAC_OVERRIDE))
			return 0;

	/*
	 * Searching includes executable on directories, else just read.
	 */
	mask &= MAY_READ | MAY_WRITE | MAY_EXEC;
	if (mask == MAY_READ)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -332,10 +332,11 @@
 
 	if (S_ISDIR(inode->i_mode)) {
 		/* DACs are overridable for directories */
-		if (inode_capable(inode, CAP_DAC_OVERRIDE))
+		if (capable_wrt_inode_uidgid(inode, CAP_DAC_OVERRIDE))
 			return 0;
 		if (!(mask & MAY_WRITE))
-			if (inode_capable(inode, CAP_DAC_READ_SEARCH))
+			if (capable_wrt_inode_uidgid(inode,
+						     CAP_DAC_READ_SEARCH))
 				return 0;
 		return -EACCES;
 	}
@@ -345,7 +346,7 @@
 	 * at least one exec bit set.
 	 */
 	if (!(mask & MAY_EXEC) || (inode->i_mode & S_IXUGO))
-		if (inode_capable(inode, CAP_DAC_OVERRIDE))
+		if (capable_wrt_inode_uidgid(inode, CAP_DAC_OVERRIDE))
 			return 0;
 
 	/*
@@ -353,7 +354,7 @@
 	 */
 	mask &= MAY_READ | MAY_WRITE | MAY_EXEC;
 	if (mask == MAY_READ)
-		if (inode_capable(inode, CAP_DAC_READ_SEARCH))
+		if (capable_wrt_inode_uidgid(inode, CAP_DAC_READ_SEARCH))
 			return 0;
 
 	return -EACCES;
@@ -2379,7 +2380,7 @@
 		return 0;
 	if (uid_eq(dir->i_uid, fsuid))
 		return 0;
-	return !inode_capable(inode, CAP_FOWNER);
+	return !capable_wrt_inode_uidgid(inode, CAP_FOWNER);
 }
 
 /*
```
