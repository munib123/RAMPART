# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in c
**Pair ID:** 3273_0
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3273_0`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```c
Lines 189-229 of the vulnerable file.

	dnli->isave = i;
    }
    return dn;
}

static int fsmSetFCaps(const char *path, const char *captxt)
{
    int rc = 0;
#if WITH_CAP
    if (captxt && *captxt != '\0') {
	cap_t fcaps = cap_from_text(captxt);
	if (fcaps == NULL || cap_set_file(path, fcaps) != 0) {
	    rc = RPMERR_SETCAP_FAILED;
	}
	cap_free(fcaps);
    } 
#endif
    return rc;
}

/** \ingroup payload
 * Create file from payload stream.
 * @return		0 on success
 */
static int expandRegular(rpmfi fi, const char *dest, rpmpsm psm, int nodigest, int nocontent)
{
    FD_t wfd = NULL;
    int rc = 0;

    /* Create the file with 0200 permissions (write by owner). */
    {
	mode_t old_umask = umask(0577);
	wfd = Fopen(dest, "w.ufdio");
	umask(old_umask);
    }
    if (Ferror(wfd)) {
	rc = RPMERR_OPEN_FAILED;
	goto exit;
    }

    if (!nocontent)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -206,11 +206,22 @@
     return rc;
 }
 
+/* Check dest is the same, empty and regular file with writeonly permissions */
+static int linkSane(FD_t wfd, const char *dest)
+{
+    struct stat sb, lsb;
+
+    return (fstat(Fileno(wfd), &sb) == 0 && sb.st_size == 0 &&
+	    (sb.st_mode & ~S_IFMT) == S_IWUSR &&
+	    lstat(dest, &lsb) == 0 && S_ISREG(lsb.st_mode) &&
+	    sb.st_dev == lsb.st_dev && sb.st_ino == lsb.st_ino);
+}
+
 /** \ingroup payload
  * Create file from payload stream.
  * @return		0 on success
  */
-static int expandRegular(rpmfi fi, const char *dest, rpmpsm psm, int nodigest, int nocontent)
+static int expandRegular(rpmfi fi, const char *dest, rpmpsm psm, int exclusive, int nodigest, int nocontent)
 {
     FD_t wfd = NULL;
     int rc = 0;
@@ -218,8 +229,14 @@
     /* Create the file with 0200 permissions (write by owner). */
     {
 	mode_t old_umask = umask(0577);
-	wfd = Fopen(dest, "w.ufdio");
+	wfd = Fopen(dest, exclusive ? "wx.ufdio" : "a.ufdio");
 	umask(old_umask);
+
+	/* If reopening, make sure the file is what we expect */
+	if (!exclusive && wfd != NULL && !linkSane(wfd, dest)) {
+	    rc = RPMERR_OPEN_FAILED;
+	    goto exit;
+	}
     }
     if (Ferror(wfd)) {
 	rc = RPMERR_OPEN_FAILED;
@@ -248,7 +265,7 @@
 	/* Create first hardlinked file empty */
 	if (*firsthardlink < 0) {
 	    *firsthardlink = rpmfiFX(fi);
-	    rc = expandRegular(fi, dest, psm, nodigest, 1);
+	    rc = expandRegular(fi, dest, psm, 1, nodigest, 1);
 	} else {
 	    /* Create hard links for others */
 	    char *fn = rpmfilesFN(files, *firsthardlink);
@@ -263,10 +280,10 @@
        existing) file with content */
     if (numHardlinks<=1) {
 	if (!rc)
-	    rc = expandRegular(fi, dest, psm, nodigest, 0);
+	    rc = expandRegular(fi, dest, psm, 1, nodigest, 0);
     } else if (rpmfiArchiveHasContent(fi)) {
 	if (!rc)
-	    rc = expandRegular(fi, dest, psm, nodigest, 0);
+	    rc = expandRegular(fi, dest, psm, 0, nodigest, 0);
 	*firsthardlink = -1;
     } else {
 	*setmeta = 0;
@@ -939,7 +956,7 @@
 	    /* we skip the hard linked file containing the content */
 	    /* write the content to the first used instead */
 	    char *fn = rpmfilesFN(files, firsthardlink);
-	    rc = expandRegular(fi, fn, psm, nodigest, 0);
+	    rc = expandRegular(fi, fn, psm, 0, nodigest, 0);
 	    firsthardlink = -1;
 	    free(fn);
 	}
```
