# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in c
**Pair ID:** 3271_0
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3271_0`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```c
Lines 77-119 of the vulnerable file.

    case RPMFILE_STATE_WRONGCOLOR:
	/*
	 * Files with wrong color are supposed to share some attributes
	 * with the actually installed file - verify what we can.
	 */
	flags &= ~(RPMVERIFY_FILEDIGEST | RPMVERIFY_FILESIZE |
		   RPMVERIFY_MTIME | RPMVERIFY_RDEV);
	break;
    case RPMFILE_STATE_NORMAL:
    /* File from a non-installed package, try to verify nevertheless */
    case RPMFILE_STATE_MISSING:
	break;
    }

    if (fn == NULL || lstat(fn, &sb) != 0) {
	vfy |= RPMVERIFY_LSTATFAIL;
	goto exit;
    }

    /* If we expected a directory but got a symlink to one, follow the link */
    if (S_ISDIR(fmode) && S_ISLNK(sb.st_mode) && stat(fn, &sb) != 0) {
	vfy |= RPMVERIFY_LSTATFAIL;
	goto exit;
    }

    /* Links have no mode, other types have no linkto */
    if (S_ISLNK(sb.st_mode))
	flags &= ~(RPMVERIFY_MODE);
    else
	flags &= ~(RPMVERIFY_LINKTO);

    /* Not all attributes of non-regular files can be verified */
    if (!S_ISREG(sb.st_mode))
	flags &= ~(RPMVERIFY_FILEDIGEST | RPMVERIFY_FILESIZE |
		   RPMVERIFY_MTIME | RPMVERIFY_CAPS);

    /* Content checks of %ghost files are meaningless. */
    if (fileAttrs & RPMFILE_GHOST)
	flags &= ~(RPMVERIFY_FILEDIGEST | RPMVERIFY_FILESIZE |
		   RPMVERIFY_MTIME | RPMVERIFY_LINKTO);

    /* Don't verify any features in omitMask. */
    flags &= ~(omitMask | RPMVERIFY_FAILURES);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -94,9 +94,18 @@
     }
 
     /* If we expected a directory but got a symlink to one, follow the link */
-    if (S_ISDIR(fmode) && S_ISLNK(sb.st_mode) && stat(fn, &sb) != 0) {
-	vfy |= RPMVERIFY_LSTATFAIL;
-	goto exit;
+    if (S_ISDIR(fmode) && S_ISLNK(sb.st_mode)) {
+	struct stat dsb;
+	/* ...if it actually points to a directory  */
+	if (stat(fn, &dsb) == 0 && S_ISDIR(dsb.st_mode)) {
+	    uid_t fuid;
+	    /* ...and is by a legit user, to match fsmVerify() behavior */
+	    if (sb.st_uid == 0 ||
+			(rpmugUid(rpmfilesFUser(fi, ix), &fuid) == 0 &&
+			 sb.st_uid == fuid)) {
+		sb = dsb; /* struct assignment */
+	    }
+	}
     }
 
     /* Links have no mode, other types have no linkto */
```
