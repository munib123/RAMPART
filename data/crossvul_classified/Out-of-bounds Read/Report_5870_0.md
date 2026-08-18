# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 5870_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5870_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 22-63 of the vulnerable file.

		  as each column is mapped from src to dst image. This lets
		  us omit having to allocate a temporary full horizontal stretch
		  of the src image.

		- If none of the src pixels within a sampling region differ,
		  then the output pixel is forced to equal (any of) the source pixel.
		  This ensures that filters do not corrupt areas of constant color.

		- Filter weight contribution results, after summing, are
		  rounded to the nearest pixel color value instead of
		  being casted to ILubyte (usually an int or char). Otherwise,
		  artifacting occurs.

*/

/*
	Additional functions are available for simple rotation or up/downscaling.
	downscaling using the fixed point implementations are usually much faster
	than the existing gdImageCopyResampled while having a similar or better
	quality.
	
	For image rotations, the optimized versions have a lazy antialiasing for 
	the edges of the images. For a much better antialiased result, the affine
	function is recommended.
*/

/*
TODO:
 - Optimize pixel accesses and loops once we have continuous buffer
 - Add scale support for a portion only of an image (equivalent of copyresized/resampled)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include <gd.h>
#include "gdhelpers.h"

#ifdef _MSC_VER
# pragma optimize("t", on)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -39,8 +39,8 @@
 	downscaling using the fixed point implementations are usually much faster
 	than the existing gdImageCopyResampled while having a similar or better
 	quality.
-	
-	For image rotations, the optimized versions have a lazy antialiasing for 
+
+	For image rotations, the optimized versions have a lazy antialiasing for
 	the edges of the images. For a much better antialiased result, the affine
 	function is recommended.
 */
@@ -633,7 +633,7 @@
 	}
 }
 
-static inline int _setEdgePixel(const gdImagePtr src, unsigned int x, unsigned int y, gdFixed coverage, const int bgColor) 
+static inline int _setEdgePixel(const gdImagePtr src, unsigned int x, unsigned int y, gdFixed coverage, const int bgColor)
 {
 	const gdFixed f_127 = gd_itofx(127);
 	register int c = src->tpixels[y][x];
@@ -934,9 +934,6 @@
         double dTotalWeight = 0.0;
 		int iSrc;
 
-        res->ContribRow[u].Left = iLeft;
-        res->ContribRow[u].Right = iRight;
-
         /* Cut edge points to fit in filter window in case of spill-off */
         if (iRight - iLeft + 1 > windows_size)  {
             if (iLeft < ((int)src_size - 1 / 2))  {
@@ -945,6 +942,9 @@
                 iRight--;
             }
         }
+
+        res->ContribRow[u].Left = iLeft;
+        res->ContribRow[u].Right = iRight;
 
         for (iSrc = iLeft; iSrc <= iRight; iSrc++) {
             dTotalWeight += (res->ContribRow[u].Weights[iSrc-iLeft] =  scale_f_d * (*pFilter)(scale_f_d * (dCenter - (double)iSrc)));
@@ -2273,7 +2273,7 @@
 	if (!src->trueColor) {
 		gdImagePaletteToTrueColor(src);
 	}
-	
+
 	/* Translate to dst origin (0,0) */
 	gdAffineTranslate(m, -bbox.x, -bbox.y);
 	gdAffineConcat(m, affine, m);
@@ -2332,7 +2332,7 @@
 	if (src->interpolation_id == GD_BILINEAR_FIXED || src->interpolation_id == GD_BICUBIC_FIXED || src->interpolation_id == GD_NEAREST_NEIGHBOUR) {
 		interpolation_id_bak = src->interpolation_id;
 		interpolation_bak = src->interpolation;
-		
+
 		gdImageSetInterpolationMethod(src, GD_BICUBIC);
 	}
 
```
