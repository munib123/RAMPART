# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5513_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5513_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1730-1770 of the vulnerable file.

		if (style & gdNoFill) {
			if (style & gdEdged) {
				gdImageLine(im, cx, cy, lx, ly, color);
				gdImageLine(im, cx, cy, fx, fy, color);
			}
		} else {
			pts[pti].x = cx;
			pts[pti].y = cy;
			gdImageFilledPolygon(im, pts, pti+1, color);
		}
	}
}

void gdImageFillToBorder (gdImagePtr im, int x, int y, int border, int color)
{
	int lastBorder;
	/* Seek left */
	int leftLimit = -1, rightLimit;
	int i, restoreAlphaBlending = 0;

	if (border < 0) {
		/* Refuse to fill to a non-solid border */
		return;
	}

	if (!im->trueColor) {
		if ((color > (im->colorsTotal - 1)) || (border > (im->colorsTotal - 1)) || (color < 0)) {
			return;
		}
	}

	restoreAlphaBlending = im->alphaBlendingFlag;
	im->alphaBlendingFlag = 0;

	if (x >= im->sx) {
		x = im->sx - 1;
	} else if (x < 0) {
		x = 0;
	}
	if (y >= im->sy) {
		y = im->sy - 1;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1747,7 +1747,7 @@
 	int leftLimit = -1, rightLimit;
 	int i, restoreAlphaBlending = 0;
 
-	if (border < 0) {
+	if (border < 0 || color < 0) {
 		/* Refuse to fill to a non-solid border */
 		return;
 	}
```
