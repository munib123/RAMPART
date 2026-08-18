# CrossVul Fix Pair: Double Free in c
**Pair ID:** 1406_1
**Vulnerability Class:** Double Free
**CWE:** CWE-415
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1406_1`)

## Vulnerability Information & PoC

## Description
Double Free - When a program calls free() twice with the same argument, the program's memory management data structures become corrupted.

## Vulnerable Code
```c
Lines 100-140 of the vulnerable file.

{
	jmpbuf_wrapper *jmpbufw;
	char buffer[JMSG_LENGTH_MAX];

	(*cinfo->err->format_message)(cinfo, buffer);
	gd_error_ex(GD_WARNING, "gd-jpeg: JPEG library reports unrecoverable error: %s", buffer);

	jmpbufw = (jmpbuf_wrapper *)cinfo->client_data;
	jpeg_destroy(cinfo);

	if(jmpbufw != 0) {
		longjmp(jmpbufw->jmpbuf, 1);
		gd_error_ex(GD_ERROR, "gd-jpeg: EXTREMELY fatal error: longjmp returned control; terminating\n");
	} else {
		gd_error_ex(GD_ERROR, "gd-jpeg: EXTREMELY fatal error: jmpbuf unrecoverable; terminating\n");
	}

	exit(99);
}

/*
 * Write IM to OUTFILE as a JFIF-formatted JPEG image, using quality
 * QUALITY.  If QUALITY is in the range 0-100, increasing values
 * represent higher quality but also larger image size.  If QUALITY is
 * negative, the IJG JPEG library's default quality is used (which
 * should be near optimal for many applications).  See the IJG JPEG
 * library documentation for more details.
 */


/*
  Function: gdImageJpeg

    <gdImageJpeg> outputs the specified image to the specified file in
    JPEG format. The file must be open for writing. Under MSDOS and
    all versions of Windows, it is important to use "wb" as opposed to
    simply "w" as the mode when opening the file, and under Unix there
    is no penalty for doing so. <gdImageJpeg> does not close the file;
    your code must do so.

    If _quality_ is negative, the default IJG JPEG quality value (which
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -116,6 +116,8 @@
 
 	exit(99);
 }
+
+static int _gdImageJpegCtx(gdImagePtr im, gdIOCtx *outfile, int quality);
 
 /*
  * Write IM to OUTFILE as a JFIF-formatted JPEG image, using quality
@@ -231,8 +233,11 @@
 	void *rv;
 	gdIOCtx *out = gdNewDynamicCtx(2048, NULL);
 	if (out == NULL) return NULL;
-	gdImageJpegCtx(im, out, quality);
-	rv = gdDPExtractData(out, size);
+	if (!_gdImageJpegCtx(im, out, quality)) {
+		rv = gdDPExtractData(out, size);
+	} else {
+		rv = NULL;
+	}
 	out->gd_free(out);
 	return rv;
 }
@@ -253,6 +258,12 @@
 
 */
 BGD_DECLARE(void) gdImageJpegCtx(gdImagePtr im, gdIOCtx *outfile, int quality)
+{
+	_gdImageJpegCtx(im, outfile, quality);
+}
+
+/* returns 0 on success, 1 on failure */
+static int _gdImageJpegCtx(gdImagePtr im, gdIOCtx *outfile, int quality)
 {
 	struct jpeg_compress_struct cinfo;
 	struct jpeg_error_mgr jerr;
@@ -287,7 +298,7 @@
 		if(row) {
 			gdFree(row);
 		}
-		return;
+		return 1;
 	}
 
 	cinfo.err->emit_message = jpeg_emit_message;
@@ -328,7 +339,7 @@
 	if(row == 0) {
 		gd_error("gd-jpeg: error: unable to allocate JPEG row structure: gdCalloc returns NULL\n");
 		jpeg_destroy_compress(&cinfo);
-		return;
+		return 1;
 	}
 
 	rowptr[0] = row;
@@ -405,6 +416,7 @@
 	jpeg_finish_compress(&cinfo);
 	jpeg_destroy_compress(&cinfo);
 	gdFree(row);
+	return 0;
 }
 
 
```
