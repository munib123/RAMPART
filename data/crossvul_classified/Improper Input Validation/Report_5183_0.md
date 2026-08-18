# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5183_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5183_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 119-159 of the vulnerable file.


BGD_DECLARE(gdImagePtr) gdImageCropThreshold(gdImagePtr im, const unsigned int color, const float threshold)
{
	const int width = gdImageSX(im);
	const int height = gdImageSY(im);

	int x,y;
	int match;
	gdRect crop;

	crop.x = 0;
	crop.y = 0;
	crop.width = 0;
	crop.height = 0;

	/* Pierre: crop everything sounds bad */
	if (threshold > 100.0) {
		return NULL;
	}

	/* TODO: Add gdImageGetRowPtr and works with ptr at the row level
	 * for the true color and palette images
	 * new formats will simply work with ptr
	 */
	match = 1;
	for (y = 0; match && y < height; y++) {
		for (x = 0; match && x < width; x++) {
			match = (gdColorMatch(im, color, gdImageGetPixel(im, x,y), threshold)) > 0;
		}
	}

	/* Pierre
	 * Nothing to do > bye
	 * Duplicate the image?
	 */
	if (y == height - 1) {
		return NULL;
	}

	crop.y = y -1;
	match = 1;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -136,6 +136,10 @@
 		return NULL;
 	}
 
+	if (color < 0 || (!gdImageTrueColor(im) && color >= gdImageColorsTotal(im))) {
+		return NULL;
+	}
+
 	/* TODO: Add gdImageGetRowPtr and works with ptr at the row level
 	 * for the true color and palette images
 	 * new formats will simply work with ptr
```
