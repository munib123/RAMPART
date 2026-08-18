# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 5256_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5256_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 82-122 of the vulnerable file.

# ifdef HAVE_LIBFREETYPE
#  include <ft2build.h>
#  include FT_FREETYPE_H
# endif
#endif

#if defined(HAVE_GD_XPM) && defined(HAVE_GD_BUNDLED)
# include "X11/xpm.h"
#endif

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

#ifdef ENABLE_GD_TTF
static void php_imagettftext_common(INTERNAL_FUNCTION_PARAMETERS, int, int);
#endif

#include "gd_ctx.c"

/* as it is not really public, duplicate declaration here to avoid 
   pointless warnings */
int overflow2(int a, int b);

/* Section Filters Declarations */
/* IMPORTANT NOTE FOR NEW FILTER
 * Do not forget to update:
 * IMAGE_FILTER_MAX: define the last filter index
 * IMAGE_FILTER_MAX_ARGS: define the biggest amount of arguments
 * image_filter array in PHP_FUNCTION(imagefilter)
 * */
#define IMAGE_FILTER_NEGATE         0
#define IMAGE_FILTER_GRAYSCALE      1
#define IMAGE_FILTER_BRIGHTNESS     2
#define IMAGE_FILTER_CONTRAST       3
#define IMAGE_FILTER_COLORIZE       4
#define IMAGE_FILTER_EDGEDETECT     5
#define IMAGE_FILTER_EMBOSS         6
#define IMAGE_FILTER_GAUSSIAN_BLUR  7
#define IMAGE_FILTER_SELECTIVE_BLUR 8
#define IMAGE_FILTER_MEAN_REMOVAL   9
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -99,7 +99,7 @@
 
 #include "gd_ctx.c"
 
-/* as it is not really public, duplicate declaration here to avoid 
+/* as it is not really public, duplicate declaration here to avoid
    pointless warnings */
 int overflow2(int a, int b);
 
@@ -1197,7 +1197,7 @@
 	REGISTER_LONG_CONSTANT("IMG_CROP_SIDES", GD_CROP_SIDES, CONST_CS | CONST_PERSISTENT);
 	REGISTER_LONG_CONSTANT("IMG_CROP_THRESHOLD", GD_CROP_THRESHOLD, CONST_CS | CONST_PERSISTENT);
 
-	
+
 	REGISTER_LONG_CONSTANT("IMG_BELL", GD_BELL, CONST_CS | CONST_PERSISTENT);
 	REGISTER_LONG_CONSTANT("IMG_BESSEL", GD_BESSEL, CONST_CS | CONST_PERSISTENT);
 	REGISTER_LONG_CONSTANT("IMG_BILINEAR_FIXED", GD_BILINEAR_FIXED, CONST_CS | CONST_PERSISTENT);
@@ -1651,11 +1651,11 @@
 
 	ZEND_FETCH_RESOURCE(im, gdImagePtr, &IM, -1, "Image", le_gd);
 
-	if (ncolors <= 0) {
-		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Number of colors has to be greater than zero");
-		RETURN_FALSE;
-	}
-	gdImageTrueColorToPalette(im, dither, ncolors);
+	if (ncolors <= 0 || ncolors > INT_MAX) {
+		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Number of colors has to be greater than zero and no more than %d", INT_MAX);
+		RETURN_FALSE;
+	}
+	gdImageTrueColorToPalette(im, dither, (int)ncolors);
 
 	RETURN_TRUE;
 }
@@ -3906,7 +3906,7 @@
 #endif /* VIRTUAL_DIR */
 
 	PHP_GD_CHECK_OPEN_BASEDIR(fontname, "Invalid font filename");
-	
+
 #ifdef HAVE_GD_FREETYPE
 	if (extended) {
 		error = gdImageStringFTEx(im, brect, col, fontname, ptsize, angle, x, y, str, &strex);
@@ -4484,7 +4484,7 @@
 	int x, y;
 	float x_ratio, y_ratio;
     long ignore_warning;
-	
+
 	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "pplll", &f_org, &f_org_len, &f_dest, &f_dest_len, &height, &width, &threshold) == FAILURE) {
 		return;
 	}
@@ -5367,7 +5367,7 @@
 				php_error_docref(NULL TSRMLS_CC, E_WARNING, "Missing y position");
 				RETURN_FALSE;
 			}
-			
+
 			if (type == GD_AFFINE_TRANSLATE) {
 				res = gdAffineTranslate(affine, x, y);
 			} else {
```
