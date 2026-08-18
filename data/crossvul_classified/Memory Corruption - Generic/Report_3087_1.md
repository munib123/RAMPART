# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 3087_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3087_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 574-614 of the vulnerable file.

	{ TIFFTAG_YCBCRPOSITIONING,	1, TIFF_SHORT },
	{ TIFFTAG_REFERENCEBLACKWHITE,	(uint16) -1,TIFF_RATIONAL },
	{ TIFFTAG_EXTRASAMPLES,		(uint16) -1, TIFF_SHORT },
	{ TIFFTAG_SMINSAMPLEVALUE,	1, TIFF_DOUBLE },
	{ TIFFTAG_SMAXSAMPLEVALUE,	1, TIFF_DOUBLE },
	{ TIFFTAG_STONITS,		1, TIFF_DOUBLE },
};
#define	NTAGS	(sizeof (tags) / sizeof (tags[0]))

#define	CopyTag(tag, count, type)	cpTag(in, out, tag, count, type)

typedef int (*copyFunc)
    (TIFF* in, TIFF* out, uint32 l, uint32 w, uint16 samplesperpixel);
static	copyFunc pickCopyFunc(TIFF*, TIFF*, uint16, uint16);

/* PODD */

static int
tiffcp(TIFF* in, TIFF* out)
{
	uint16 bitspersample, samplesperpixel = 1;
	uint16 input_compression, input_photometric = PHOTOMETRIC_MINISBLACK;
	copyFunc cf;
	uint32 width, length;
	struct cpTag* p;

	CopyField(TIFFTAG_IMAGEWIDTH, width);
	CopyField(TIFFTAG_IMAGELENGTH, length);
	CopyField(TIFFTAG_BITSPERSAMPLE, bitspersample);
	CopyField(TIFFTAG_SAMPLESPERPIXEL, samplesperpixel);
	if (compression != (uint16)-1)
		TIFFSetField(out, TIFFTAG_COMPRESSION, compression);
	else
		CopyField(TIFFTAG_COMPRESSION, compression);
	TIFFGetFieldDefaulted(in, TIFFTAG_COMPRESSION, &input_compression);
	TIFFGetFieldDefaulted(in, TIFFTAG_PHOTOMETRIC, &input_photometric);
	if (input_compression == COMPRESSION_JPEG) {
		/* Force conversion to RGB */
		TIFFSetField(in, TIFFTAG_JPEGCOLORMODE, JPEGCOLORMODE_RGB);
	} else if (input_photometric == PHOTOMETRIC_YCBCR) {
		/* Otherwise, can't handle subsampled input */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -591,7 +591,7 @@
 static int
 tiffcp(TIFF* in, TIFF* out)
 {
-	uint16 bitspersample, samplesperpixel = 1;
+	uint16 bitspersample = 1, samplesperpixel = 1;
 	uint16 input_compression, input_photometric = PHOTOMETRIC_MINISBLACK;
 	copyFunc cf;
 	uint32 width, length;
@@ -1067,6 +1067,16 @@
 	register uint32 n;
 	uint32 row;
 	tsample_t s;
+        uint16 bps = 0;
+
+        (void) TIFFGetField(in, TIFFTAG_BITSPERSAMPLE, &bps);
+        if( bps != 8 )
+        {
+            TIFFError(TIFFFileName(in),
+                      "Error, can only handle BitsPerSample=8 in %s",
+                      "cpContig2SeparateByRow");
+            return 0;
+        }
 
 	inbuf = _TIFFmalloc(scanlinesizein);
 	outbuf = _TIFFmalloc(scanlinesizeout);
@@ -1120,6 +1130,16 @@
 	register uint32 n;
 	uint32 row;
 	tsample_t s;
+        uint16 bps = 0;
+
+        (void) TIFFGetField(in, TIFFTAG_BITSPERSAMPLE, &bps);
+        if( bps != 8 )
+        {
+            TIFFError(TIFFFileName(in),
+                      "Error, can only handle BitsPerSample=8 in %s",
+                      "cpSeparate2ContigByRow");
+            return 0;
+        }
 
 	inbuf = _TIFFmalloc(scanlinesizein);
 	outbuf = _TIFFmalloc(scanlinesizeout);
@@ -1784,7 +1804,7 @@
 	uint32 w, l, tw, tl;
 	int bychunk;
 
-	(void) TIFFGetField(in, TIFFTAG_PLANARCONFIG, &shortv);
+	(void) TIFFGetFieldDefaulted(in, TIFFTAG_PLANARCONFIG, &shortv);
 	if (shortv != config && bitspersample != 8 && samplesperpixel > 1) {
 		fprintf(stderr,
 		    "%s: Cannot handle different planar configuration w/ bits/sample != 8\n",
```
