# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 5480_1
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5480_1`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 575-616 of the vulnerable file.

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
	uint16 bitspersample, samplesperpixel;
	uint16 input_compression, input_photometric;
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
		uint16 subsamplinghor,subsamplingver;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -592,8 +592,8 @@
 static int
 tiffcp(TIFF* in, TIFF* out)
 {
-	uint16 bitspersample, samplesperpixel;
-	uint16 input_compression, input_photometric;
+	uint16 bitspersample, samplesperpixel = 1;
+	uint16 input_compression, input_photometric = PHOTOMETRIC_MINISBLACK;
 	copyFunc cf;
 	uint32 width, length;
 	struct cpTag* p;
```
