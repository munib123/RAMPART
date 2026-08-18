# CrossVul Fix Pair: Double Free in c
**Pair ID:** 1407_1
**Vulnerability Class:** Double Free
**CWE:** CWE-415
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1407_1`)

## Vulnerability Information & PoC

## Description
Double Free - When a program calls free() twice with the same argument, the program's memory management data structures become corrupted.

## Vulnerable Code
```c
Lines 115-155 of the vulnerable file.

			return "6b";
			break;

		case 70:
			return "7";
			break;

		case 80:
			return "8";
			break;

		case 90:
			return "9 compatible";
			break;

		default:
			return "unknown";
	}
}


/*
 * Write IM to OUTFILE as a JFIF-formatted JPEG image, using quality
 * QUALITY.  If QUALITY is in the range 0-100, increasing values
 * represent higher quality but also larger image size.  If QUALITY is
 * negative, the IJG JPEG library's default quality is used (which
 * should be near optimal for many applications).  See the IJG JPEG
 * library documentation for more details.
 */

void gdImageJpeg (gdImagePtr im, FILE * outFile, int quality)
{
	gdIOCtx *out = gdNewFileCtx (outFile);
	gdImageJpegCtx (im, out, quality);
	out->gd_free (out);
}

void *gdImageJpegPtr (gdImagePtr im, int *size, int quality)
{
	void *rv;
	gdIOCtx *out = gdNewDynamicCtx (2048, NULL);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -132,6 +132,7 @@
 	}
 }
 
+static int _gdImageJpegCtx(gdImagePtr im, gdIOCtx *outfile, int quality);
 
 /*
  * Write IM to OUTFILE as a JFIF-formatted JPEG image, using quality
@@ -153,8 +154,11 @@
 {
 	void *rv;
 	gdIOCtx *out = gdNewDynamicCtx (2048, NULL);
-	gdImageJpegCtx (im, out, quality);
-	rv = gdDPExtractData (out, size);
+	if (!_gdImageJpegCtx(im, out, quality)) {
+		rv = gdDPExtractData(out, size);
+	} else {
+		rv = NULL;
+	}
 	out->gd_free (out);
 
 	return rv;
@@ -163,6 +167,12 @@
 void jpeg_gdIOCtx_dest (j_compress_ptr cinfo, gdIOCtx * outfile);
 
 void gdImageJpegCtx (gdImagePtr im, gdIOCtx * outfile, int quality)
+{
+	_gdImageJpegCtx(im, outfile, quality);
+}
+
+/* returns 0 on success, 1 on failure */
+static int _gdImageJpegCtx(gdImagePtr im, gdIOCtx *outfile, int quality)
 {
 	struct jpeg_compress_struct cinfo;
 	struct jpeg_error_mgr jerr;
@@ -184,7 +194,7 @@
 		if (row) {
 			gdFree (row);
 		}
-		return;
+		return 1;
 	}
 
 	cinfo.err->error_exit = fatal_jpeg_error;
@@ -277,6 +287,7 @@
 	jpeg_finish_compress (&cinfo);
 	jpeg_destroy_compress (&cinfo);
 	gdFree (row);
+	return 0;
 }
 
 gdImagePtr gdImageCreateFromJpeg (FILE * inFile)
```
