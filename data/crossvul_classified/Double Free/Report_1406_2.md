# CrossVul Fix Pair: Double Free in c
**Pair ID:** 1406_2
**Vulnerability Class:** Double Free
**CWE:** CWE-415
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1406_2`)

## Vulnerability Information & PoC

## Description
Double Free - When a program calls free() twice with the same argument, the program's memory management data structures become corrupted.

## Vulnerable Code
```c
Lines 71-111 of the vulnerable file.

#include "wbmp.h"

/* gd_putout
 * ---------
 * Wrapper around gdPutC for use with writewbmp
 */
void gd_putout(int i, void *out)
{
	gdPutC(i, (gdIOCtx *)out);
}

/* gd_getin
 * --------
 * Wrapper around gdGetC for use with readwbmp
 */
int gd_getin(void *in)
{
	return (gdGetC((gdIOCtx *)in));
}

/*
	Function: gdImageWBMPCtx

	Write the image as a wbmp file

	Parameters:
		image - gd image structure
		fg    - the index of the foreground color. any other value will be
				considered as background and will not be written
		out   - the stream where to write
*/
BGD_DECLARE(void) gdImageWBMPCtx(gdImagePtr image, int fg, gdIOCtx *out)
{
	int x, y, pos;
	Wbmp *wbmp;

	/* create the WBMP */
	if((wbmp = createwbmp(gdImageSX(image), gdImageSY(image), WBMP_WHITE)) == NULL) {
		gd_error("Could not create WBMP\n");
		return;
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -88,6 +88,8 @@
 	return (gdGetC((gdIOCtx *)in));
 }
 
+static int _gdImageWBMPCtx(gdImagePtr image, int fg, gdIOCtx *out);
+
 /*
 	Function: gdImageWBMPCtx
 
@@ -101,13 +103,19 @@
 */
 BGD_DECLARE(void) gdImageWBMPCtx(gdImagePtr image, int fg, gdIOCtx *out)
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
 	if((wbmp = createwbmp(gdImageSX(image), gdImageSY(image), WBMP_WHITE)) == NULL) {
 		gd_error("Could not create WBMP\n");
-		return;
+		return 1;
 	}
 
 	/* fill up the WBMP structure */
@@ -123,11 +131,15 @@
 
 	/* write the WBMP to a gd file descriptor */
 	if(writewbmp(wbmp, &gd_putout, out)) {
+		freewbmp(wbmp);
 		gd_error("Could not save WBMP\n");
+		return 1;
 	}
 
 	/* des submitted this bugfix: gdFree the memory. */
 	freewbmp(wbmp);
+
+	return 0;
 }
 
 /*
@@ -271,8 +283,11 @@
 	void *rv;
 	gdIOCtx *out = gdNewDynamicCtx(2048, NULL);
 	if (out == NULL) return NULL;
-	gdImageWBMPCtx(im, fg, out);
-	rv = gdDPExtractData(out, size);
+	if (!_gdImageWBMPCtx(im, fg, out)) {
+		rv = gdDPExtractData(out, size);
+	} else {
+		rv = NULL;
+	}
 	out->gd_free(out);
 	return rv;
 }
```
