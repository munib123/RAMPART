# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in c
**Pair ID:** 3272_0
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3272_0`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```c
Lines 633-673 of the vulnerable file.

	{ .tv_sec = mtime, .tv_usec = 0 },
    };

#if HAVE_LUTIMES
    rc = lutimes(path, stamps);
#else
    if (!S_ISLNK(mode))
	rc = utimes(path, stamps);
#endif
    
    if (_fsm_debug)
	rpmlog(RPMLOG_DEBUG, " %8s (%s, 0x%x) %s\n", __func__,
	       path, (unsigned)mtime, (rc < 0 ? strerror(errno) : ""));
    if (rc < 0)	rc = RPMERR_UTIME_FAILED;
    /* ...but utime error is not critical for directories */
    if (rc && S_ISDIR(mode))
	rc = 0;
    return rc;
}

static int fsmVerify(const char *path, rpmfi fi)
{
    int rc;
    int saveerrno = errno;
    struct stat dsb;
    mode_t mode = rpmfiFMode(fi);

    rc = fsmStat(path, 1, &dsb);
    if (rc)
	return rc;

    if (S_ISREG(mode)) {
	/* HP-UX (and other os'es) don't permit unlink on busy files. */
	char *rmpath = rstrscat(NULL, path, "-RPMDELETE", NULL);
	rc = fsmRename(path, rmpath);
	/* XXX shouldn't we take unlink return code here? */
	if (!rc)
	    (void) fsmUnlink(rmpath);
	else
	    rc = RPMERR_UNLINK_FAILED;
	free(rmpath);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -650,7 +650,7 @@
     return rc;
 }
 
-static int fsmVerify(const char *path, rpmfi fi)
+static int fsmVerify(const char *path, rpmfi fi, const struct stat *fsb)
 {
     int rc;
     int saveerrno = errno;
@@ -675,11 +675,14 @@
     } else if (S_ISDIR(mode)) {
         if (S_ISDIR(dsb.st_mode)) return 0;
         if (S_ISLNK(dsb.st_mode)) {
+	    uid_t luid = dsb.st_uid;
             rc = fsmStat(path, 0, &dsb);
             if (rc == RPMERR_ENOENT) rc = 0;
             if (rc) return rc;
             errno = saveerrno;
-            if (S_ISDIR(dsb.st_mode)) return 0;
+	    /* Only permit directory symlinks by target owner and root */
+            if (S_ISDIR(dsb.st_mode) && (luid == 0 || luid == fsb->st_uid))
+		    return 0;
         }
     } else if (S_ISLNK(mode)) {
         if (S_ISLNK(dsb.st_mode)) {
@@ -921,7 +924,7 @@
 	    }
 	    /* Assume file does't exist when tmp suffix is in use */
 	    if (!suffix) {
-		rc = fsmVerify(fpath, fi);
+		rc = fsmVerify(fpath, fi, &sb);
 	    } else {
 		rc = (action == FA_TOUCH) ? 0 : RPMERR_ENOENT;
 	    }
```
