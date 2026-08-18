# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 270_2
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `270_2`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1-26 of the vulnerable file.

/*
 * rdbmp.c
 *
 * This file was part of the Independent JPEG Group's software:
 * Copyright (C) 1994-1996, Thomas G. Lane.
 * Modified 2009-2010 by Guido Vollbeding.
 * libjpeg-turbo Modifications:
 * Modified 2011 by Siarhei Siamashka.
 * Copyright (C) 2015, 2017-2018, D. R. Commander.
 * For conditions of distribution and use, see the accompanying README.ijg
 * file.
 *
 * This file contains routines to read input images in Microsoft "BMP"
 * format (MS Windows 3.x, OS/2 1.x, and OS/2 2.x flavors).
 * Currently, only 8-bit and 24-bit images are supported, not 1-bit or
 * 4-bit (feeding such low-depth images into JPEG would be silly anyway).
 * Also, we don't support RLE-compressed files.
 *
 * These routines may need modification for non-Unix environments or
 * specialized applications.  As they stand, they assume input from
 * an ordinary stdio stream.  They further assume that reading begins
 * at the start of the file; start_input may need work if the
 * user interface has already read some data (e.g., to determine that
 * the file is indeed BMP format).
 *
 * This code contributed by James Arthur Boucher.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3,7 +3,7 @@
  *
  * This file was part of the Independent JPEG Group's software:
  * Copyright (C) 1994-1996, Thomas G. Lane.
- * Modified 2009-2010 by Guido Vollbeding.
+ * Modified 2009-2017 by Guido Vollbeding.
  * libjpeg-turbo Modifications:
  * Modified 2011 by Siarhei Siamashka.
  * Copyright (C) 2015, 2017-2018, D. R. Commander.
@@ -72,6 +72,7 @@
   JDIMENSION row_width;         /* Physical width of scanlines in file */
 
   int bits_per_pixel;           /* remembers 8- or 24-bit format */
+  int cmap_length;              /* colormap length */
 
   boolean use_inversion_array;  /* TRUE = preload the whole image, which is
                                    stored in bottom-up order, and feed it to
@@ -155,6 +156,7 @@
 {
   bmp_source_ptr source = (bmp_source_ptr)sinfo;
   register JSAMPARRAY colormap = source->colormap;
+  int cmaplen = source->cmap_length;
   JSAMPARRAY image_ptr;
   register int t;
   register JSAMPROW inptr, outptr;
@@ -178,11 +180,15 @@
   if (cinfo->in_color_space == JCS_GRAYSCALE) {
     for (col = cinfo->image_width; col > 0; col--) {
       t = GETJSAMPLE(*inptr++);
+      if (t >= cmaplen)
+        ERREXIT(cinfo, JERR_BMP_OUTOFRANGE);
       *outptr++ = colormap[0][t];
     }
   } else if (cinfo->in_color_space == JCS_CMYK) {
     for (col = cinfo->image_width; col > 0; col--) {
       t = GETJSAMPLE(*inptr++);
+      if (t >= cmaplen)
+        ERREXIT(cinfo, JERR_BMP_OUTOFRANGE);
       rgb_to_cmyk(colormap[0][t], colormap[1][t], colormap[2][t], outptr,
                   outptr + 1, outptr + 2, outptr + 3);
       outptr += 4;
@@ -197,6 +203,8 @@
     if (aindex >= 0) {
       for (col = cinfo->image_width; col > 0; col--) {
         t = GETJSAMPLE(*inptr++);
+        if (t >= cmaplen)
+          ERREXIT(cinfo, JERR_BMP_OUTOFRANGE);
         outptr[rindex] = colormap[0][t];
         outptr[gindex] = colormap[1][t];
         outptr[bindex] = colormap[2][t];
@@ -206,6 +214,8 @@
     } else {
       for (col = cinfo->image_width; col > 0; col--) {
         t = GETJSAMPLE(*inptr++);
+        if (t >= cmaplen)
+          ERREXIT(cinfo, JERR_BMP_OUTOFRANGE);
         outptr[rindex] = colormap[0][t];
         outptr[gindex] = colormap[1][t];
         outptr[bindex] = colormap[2][t];
@@ -539,6 +549,7 @@
     /* Allocate space to store the colormap */
     source->colormap = (*cinfo->mem->alloc_sarray)
       ((j_common_ptr)cinfo, JPOOL_IMAGE, (JDIMENSION)biClrUsed, (JDIMENSION)3);
+    source->cmap_length = (int)biClrUsed;
     /* and read it from the file */
     read_colormap(source, (int)biClrUsed, mapentrysize);
     /* account for size of colormap */
```
