# CrossVul Fix Pair: Double Free in c
**Pair ID:** 1407_2
**Vulnerability Class:** Double Free
**CWE:** CWE-415
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1407_2`)

## Vulnerability Information & PoC

## Description
Double Free - When a program calls free() twice with the same argument, the program's memory management data structures become corrupted.

## Vulnerable Code
```c
Lines 65-105 of the vulnerable file.

   ** ---------
   ** Wrapper around gdPutC for use with writewbmp
   **
 */
void gd_putout (int i, void *out)
{
	gdPutC(i, (gdIOCtx *) out);
}


/* gd_getin
   ** --------
   ** Wrapper around gdGetC for use with readwbmp
   **
 */
int gd_getin (void *in)
{
	return (gdGetC((gdIOCtx *) in));
}


/*      gdImageWBMPCtx
   **  --------------
   **  Write the image as a wbmp file
   **  Parameters are:
   **  image:  gd image structure;
   **  fg:     the index of the foreground color. any other value will be
   **          considered as background and will not be written
   **  out:    the stream where to write
 */
void gdImageWBMPCtx (gdImagePtr image, int fg, gdIOCtx * out)
{
	int x, y, pos;
	Wbmp *wbmp;

	/* create the WBMP */
	if ((wbmp = createwbmp (gdImageSX (image), gdImageSY (image), WBMP_WHITE)) == NULL) {
		gd_error("Could not create WBMP");
		return;
	}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -82,6 +82,7 @@
 	return (gdGetC((gdIOCtx *) in));
 }
 
+static int _gdImageWBMPCtx(gdImagePtr image, int fg, gdIOCtx *out);
 
 /*      gdImageWBMPCtx
    **  --------------
@@ -94,13 +95,19 @@
  */
 void gdImageWBMPCtx (gdImagePtr image, int fg, gdIOCtx * out)
 {
+	_gdImageWBMPCtx(image, fg, out);
+}
+
+/* returns 0 on success, 1 on failure */
+static int _gdImageWBMPCtx(gdImagePtr image, int fg, gdIOCtx *out)
+{
 	int x, y, pos;
 	Wbmp *wbmp;
 
 	/* create the WBMP */
 	if ((wbmp = createwbmp (gdImageSX (image), gdImageSY (image), WBMP_WHITE)) == NULL) {
 		gd_error("Could not create WBMP");
-		return;
+		return 1;
 	}
 
 	/* fill up the WBMP structure */
@@ -116,7 +123,9 @@
 
 	/* write the WBMP to a gd file descriptor */
 	if (writewbmp (wbmp, &gd_putout, out)) {
+		freewbmp(wbmp);
 		gd_error("Could not save WBMP");
+		return 1;
 	}
 	/* des submitted this bugfix: gdFree the memory. */
 	freewbmp(wbmp);
@@ -204,8 +213,11 @@
 {
 	void *rv;
 	gdIOCtx *out = gdNewDynamicCtx(2048, NULL);
-	gdImageWBMPCtx(im, fg, out);
-	rv = gdDPExtractData(out, size);
+	if (!_gdImageWBMPCtx(im, fg, out)) {
+		rv = gdDPExtractData(out, size);
+	} else {
+		rv = NULL;
+	}
 	out->gd_free(out);
 
 	return rv;
```
