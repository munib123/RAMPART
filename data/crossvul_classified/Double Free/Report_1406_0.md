# CrossVul Fix Pair: Double Free in c
**Pair ID:** 1406_0
**Vulnerability Class:** Double Free
**CWE:** CWE-415
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1406_0`)

## Vulnerability Information & PoC

## Description
Double Free - When a program calls free() twice with the same argument, the program's memory management data structures become corrupted.

## Vulnerable Code
```c
Lines 82-122 of the vulnerable file.

	unsigned long cur_accum;
	int cur_bits;
	int a_count;
	char accum[ 256 ];
} GifCtx;

static int gifPutWord(int w, gdIOCtx *out);
static int colorstobpp(int colors);
static void BumpPixel(GifCtx *ctx);
static int GIFNextPixel(gdImagePtr im, GifCtx *ctx);
static void GIFEncode(gdIOCtxPtr fp, int GWidth, int GHeight, int GInterlace, int Background, int Transparent, int BitsPerPixel, int *Red, int *Green, int *Blue, gdImagePtr im);
static void GIFAnimEncode(gdIOCtxPtr fp, int IWidth, int IHeight, int LeftOfs, int TopOfs, int GInterlace, int Transparent, int Delay, int Disposal, int BitsPerPixel, int *Red, int *Green, int *Blue, gdImagePtr im);
static void compress(int init_bits, gdIOCtx *outfile, gdImagePtr im, GifCtx *ctx);
static void output(code_int code, GifCtx *ctx);
static void cl_block(GifCtx *ctx);
static void cl_hash(register count_int chsize, GifCtx *ctx);
static void char_init(GifCtx *ctx);
static void char_out(int c, GifCtx *ctx);
static void flush_char(GifCtx *ctx);




/*
  Function: gdImageGifPtr

    Identical to <gdImageGif> except that it returns a pointer to a
    memory area with the GIF data. This memory must be freed by the
    caller when it is no longer needed.

    The caller *must* invoke <gdFree>, not _free()_.  This is because
    it is not guaranteed that libgd will use the same implementation
    of malloc, free, etc. as your proggram.

    The 'size' parameter receives the total size of the block of
    memory.

  Parameters:

    im      - The image to write
    size    - Output: the size of the resulting image.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -99,6 +99,7 @@
 static void char_out(int c, GifCtx *ctx);
 static void flush_char(GifCtx *ctx);
 
+static int _gdImageGifCtx(gdImagePtr im, gdIOCtxPtr out);
 
 
 
@@ -131,8 +132,11 @@
 	void *rv;
 	gdIOCtx *out = gdNewDynamicCtx(2048, NULL);
 	if (out == NULL) return NULL;
-	gdImageGifCtx(im, out);
-	rv = gdDPExtractData(out, size);
+	if (!_gdImageGifCtx(im, out)) {
+		rv = gdDPExtractData(out, size);
+	} else {
+		rv = NULL;
+	}
 	out->gd_free(out);
 	return rv;
 }
@@ -221,6 +225,12 @@
 */
 BGD_DECLARE(void) gdImageGifCtx(gdImagePtr im, gdIOCtxPtr out)
 {
+	_gdImageGifCtx(im, out);
+}
+
+/* returns 0 on success, 1 on failure */
+static int _gdImageGifCtx(gdImagePtr im, gdIOCtxPtr out)
+{
 	gdImagePtr pim = 0, tim = im;
 	int interlace, BitsPerPixel;
 	interlace = im->interlace;
@@ -231,7 +241,7 @@
 		based temporary image. */
 		pim = gdImageCreatePaletteFromTrueColor(im, 1, 256);
 		if(!pim) {
-			return;
+			return 1;
 		}
 		tim = pim;
 	}
@@ -247,6 +257,8 @@
 		/* Destroy palette based temporary image. */
 		gdImageDestroy(	pim);
 	}
+
+	return 0;
 }
 
 
```
