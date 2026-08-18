# CrossVul Fix Pair: Double Free in c
**Pair ID:** 5242_0
**Vulnerability Class:** Double Free
**CWE:** CWE-415
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5242_0`)

## Vulnerability Information & PoC

## Description
Double Free - When a program calls free() twice with the same argument, the program's memory management data structures become corrupted.

## Vulnerable Code
```c
Lines 145-186 of the vulnerable file.

		gdFree(temp);
		gdImageDestroy(im);
		return NULL;
	}
	for (y = 0, p = argb;  y < height; y++) {
		for (x = 0; x < width; x++) {
			register uint8_t a = gdAlphaMax - (*(p++) >> 1);
			register uint8_t r = *(p++);
			register uint8_t g = *(p++);
			register uint8_t b = *(p++);
			im->tpixels[y][x] = gdTrueColorAlpha(r, g, b, a);
		}
	}
	/* do not use gdFree here, in case gdFree/alloc is mapped to something else than libc */
	free(argb);
	gdFree(temp);
	im->saveAlphaFlag = 1;
	return im;
}

/*
  Function: gdImageWebpCtx

    Write the image as WebP data via a <gdIOCtx>. See <gdImageWebpEx>
    for more details.

  Parameters:

    im      - The image to write.
    outfile - The output sink.
    quality - Image quality.

  Returns:

    Nothing.
*/
BGD_DECLARE(void) gdImageWebpCtx (gdImagePtr im, gdIOCtx * outfile, int quality)
{
	uint8_t *argb;
	int x, y;
	uint8_t *p;
	uint8_t *out;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -162,37 +162,24 @@
 	return im;
 }
 
-/*
-  Function: gdImageWebpCtx
-
-    Write the image as WebP data via a <gdIOCtx>. See <gdImageWebpEx>
-    for more details.
-
-  Parameters:
-
-    im      - The image to write.
-    outfile - The output sink.
-    quality - Image quality.
-
-  Returns:
-
-    Nothing.
-*/
-BGD_DECLARE(void) gdImageWebpCtx (gdImagePtr im, gdIOCtx * outfile, int quality)
+
+/* returns 0 on success, 1 on failure */
+static int _gdImageWebpCtx (gdImagePtr im, gdIOCtx * outfile, int quality)
 {
 	uint8_t *argb;
 	int x, y;
 	uint8_t *p;
 	uint8_t *out;
 	size_t out_size;
+    int ret = 0;
 
 	if (im == NULL) {
-		return;
+		return 1;
 	}
 
 	if (!gdImageTrueColor(im)) {
-		gd_error("Paletter image not supported by webp");
-		return;
+		gd_error("Palette image not supported by webp");
+		return 1;
 	}
 
 	if (quality == -1) {
@@ -200,16 +187,16 @@
 	}
 
 	if (overflow2(gdImageSX(im), 4)) {
-		return;
+		return 1;
 	}
 
 	if (overflow2(gdImageSX(im) * 4, gdImageSY(im))) {
-		return;
+		return 1;
 	}
 
 	argb = (uint8_t *)gdMalloc(gdImageSX(im) * 4 * gdImageSY(im));
 	if (!argb) {
-		return;
+		return 1;
 	}
 	p = argb;
 	for (y = 0; y < gdImageSY(im); y++) {
@@ -232,6 +219,7 @@
 	out_size = WebPEncodeRGBA(argb, gdImageSX(im), gdImageSY(im), gdImageSX(im) * 4, quality, &out);
 	if (out_size == 0) {
 		gd_error("gd-webp encoding failed");
+        ret = 1;
 		goto freeargb;
 	}
 	gdPutBuf(out, out_size, outfile);
@@ -239,6 +227,30 @@
 
 freeargb:
 	gdFree(argb);
+
+    return ret;
+}
+
+
+/*
+  Function: gdImageWebpCtx
+
+    Write the image as WebP data via a <gdIOCtx>. See <gdImageWebpEx>
+    for more details.
+
+  Parameters:
+
+    im      - The image to write.
+    outfile - The output sink.
+    quality - Image quality.
+
+  Returns:
+
+    Nothing.
+*/
+BGD_DECLARE(void) gdImageWebpCtx (gdImagePtr im, gdIOCtx * outfile, int quality)
+{
+	_gdImageWebpCtx(im, outfile, quality);
 }
 
 /*
@@ -278,7 +290,7 @@
 	if (out == NULL) {
 		return;
 	}
-	gdImageWebpCtx(im, out, quality);
+	_gdImageWebpCtx(im, out, quality);
 	out->gd_free(out);
 }
 
@@ -302,7 +314,7 @@
 	if (out == NULL) {
 		return;
 	}
-	gdImageWebpCtx(im, out, -1);
+	_gdImageWebpCtx(im, out, -1);
 	out->gd_free(out);
 }
 
@@ -318,8 +330,11 @@
 	if (out == NULL) {
 		return NULL;
 	}
-	gdImageWebpCtx(im, out, -1);
-	rv = gdDPExtractData(out, size);
+	if (_gdImageWebpCtx(im, out, -1)) {
+		rv = NULL;
+	} else {
+		rv = gdDPExtractData(out, size);
+	}
 	out->gd_free(out);
 
 	return rv;
@@ -337,8 +352,11 @@
 	if (out == NULL) {
 		return NULL;
 	}
-	gdImageWebpCtx(im, out, quality);
-	rv = gdDPExtractData(out, size);
+	if (_gdImageWebpCtx(im, out, quality)) {
+        rv = NULL;
+    } else {
+        rv = gdDPExtractData(out, size);
+    }
 	out->gd_free(out);
 	return rv;
 }
```
