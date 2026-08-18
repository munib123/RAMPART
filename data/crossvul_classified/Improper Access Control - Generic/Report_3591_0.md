# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 3591_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3591_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 567-607 of the vulnerable file.

	 * but the performance tradeoff of the extra network request when EISDIR
	 * or EACCES is returned would have to be weighed against the 50%
	 * reduction in network traffic in the other paths.
	 */
	if (pTcon->unix_ext) {
		if (nd && !(nd->flags & LOOKUP_DIRECTORY) &&
		     (nd->flags & LOOKUP_OPEN) && !pTcon->broken_posix_open &&
		     (nd->intent.open.file->f_flags & O_CREAT)) {
			rc = cifs_posix_open(full_path, &newInode,
					parent_dir_inode->i_sb,
					nd->intent.open.create_mode,
					nd->intent.open.file->f_flags, &oplock,
					&fileHandle, xid);
			/*
			 * The check below works around a bug in POSIX
			 * open in samba versions 3.3.1 and earlier where
			 * open could incorrectly fail with invalid parameter.
			 * If either that or op not supported returned, follow
			 * the normal lookup.
			 */
			if ((rc == 0) || (rc == -ENOENT))
				posix_open = true;
			else if ((rc == -EINVAL) || (rc != -EOPNOTSUPP))
				pTcon->broken_posix_open = true;
		}
		if (!posix_open)
			rc = cifs_get_inode_info_unix(&newInode, full_path,
						parent_dir_inode->i_sb, xid);
	} else
		rc = cifs_get_inode_info(&newInode, full_path, NULL,
				parent_dir_inode->i_sb, xid, NULL);

	if ((rc == 0) && (newInode != NULL)) {
		d_add(direntry, newInode);
		if (posix_open) {
			filp = lookup_instantiate_filp(nd, direntry,
						       generic_file_open);
			if (IS_ERR(filp)) {
				rc = PTR_ERR(filp);
				CIFSSMBClose(xid, pTcon, fileHandle);
				goto lookup_out;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -584,10 +584,26 @@
 			 * If either that or op not supported returned, follow
 			 * the normal lookup.
 			 */
-			if ((rc == 0) || (rc == -ENOENT))
+			switch (rc) {
+			case 0:
+				/*
+				 * The server may allow us to open things like
+				 * FIFOs, but the client isn't set up to deal
+				 * with that. If it's not a regular file, just
+				 * close it and proceed as if it were a normal
+				 * lookup.
+				 */
+				if (newInode && !S_ISREG(newInode->i_mode)) {
+					CIFSSMBClose(xid, pTcon, fileHandle);
+					break;
+				}
+			case -ENOENT:
 				posix_open = true;
-			else if ((rc == -EINVAL) || (rc != -EOPNOTSUPP))
+			case -EOPNOTSUPP:
+				break;
+			default:
 				pTcon->broken_posix_open = true;
+			}
 		}
 		if (!posix_open)
 			rc = cifs_get_inode_info_unix(&newInode, full_path,
```
