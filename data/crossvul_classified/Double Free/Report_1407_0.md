# CrossVul Fix Pair: Double Free in c
**Pair ID:** 1407_0
**Vulnerability Class:** Double Free
**CWE:** CWE-415
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1407_0`)

## Vulnerability Information & PoC

## Description
Double Free - When a program calls free() twice with the same argument, the program's memory management data structures become corrupted.

## Vulnerable Code
```c
Lines 80-120 of the vulnerable file.

         */
        int a_count;
        /*
         * Define the storage for the packet accumulator
         */
        char accum[ 256 ];
} GifCtx;

static int gifPutWord(int w, gdIOCtx *out);
static int colorstobpp(int colors);
static void BumpPixel (GifCtx *ctx);
static int GIFNextPixel (gdImagePtr im, GifCtx *ctx);
static void GIFEncode (gdIOCtxPtr fp, int GWidth, int GHeight, int GInterlace, int Background, int Transparent, int BitsPerPixel, int *Red, int *Green, int *Blue, gdImagePtr im);
static void compress (int init_bits, gdIOCtx *outfile, gdImagePtr im, GifCtx *ctx);
static void output (code_int code, GifCtx *ctx);
static void cl_block (GifCtx *ctx);
static void cl_hash (register count_int chsize, GifCtx *ctx);
static void char_init (GifCtx *ctx);
static void char_out (int c, GifCtx *ctx);
static void flush_char (GifCtx *ctx);
void * gdImageGifPtr (gdImagePtr im, int *size)
{
  void *rv;
  gdIOCtx *out = gdNewDynamicCtx (2048, NULL);
  gdImageGifCtx (im, out);
  rv = gdDPExtractData (out, size);
  out->gd_free (out);
  return rv;
}

void gdImageGif (gdImagePtr im, FILE * outFile)
{
  gdIOCtx *out = gdNewFileCtx (outFile);
  gdImageGifCtx (im, out);
  out->gd_free (out);
}

void gdImageGifCtx(gdImagePtr im, gdIOCtxPtr out)
{
	gdImagePtr pim = 0, tim = im;
	int interlace, BitsPerPixel;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -97,12 +97,18 @@
 static void char_init (GifCtx *ctx);
 static void char_out (int c, GifCtx *ctx);
 static void flush_char (GifCtx *ctx);
+
+static int _gdImageGifCtx(gdImagePtr im, gdIOCtxPtr out);
+
 void * gdImageGifPtr (gdImagePtr im, int *size)
 {
   void *rv;
   gdIOCtx *out = gdNewDynamicCtx (2048, NULL);
-  gdImageGifCtx (im, out);
-  rv = gdDPExtractData (out, size);
+	if (!_gdImageGifCtx(im, out)) {
+		rv = gdDPExtractData(out, size);
+	} else {
+		rv = NULL;
+	}
   out->gd_free (out);
   return rv;
 }
@@ -115,6 +121,12 @@
 }
 
 void gdImageGifCtx(gdImagePtr im, gdIOCtxPtr out)
+{
+	_gdImageGifCtx(im, out);
+}
+
+/* returns 0 on success, 1 on failure */
+static int _gdImageGifCtx(gdImagePtr im, gdIOCtxPtr out)
 {
 	gdImagePtr pim = 0, tim = im;
 	int interlace, BitsPerPixel;
@@ -125,7 +137,7 @@
 			based temporary image. */
 		pim = gdImageCreatePaletteFromTrueColor(im, 1, 256);
 		if (!pim) {
-			return;
+			return 1;
 		}
 		tim = pim;
 	}
@@ -138,6 +150,8 @@
 		/* Destroy palette based temporary image. */
 		gdImageDestroy(	pim);
 	}
+
+    return 0;
 }
 
 static int
```
