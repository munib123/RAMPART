# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5512_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5512_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1911-1951 of the vulnerable file.

				gdImageSetPixel(im,i,my1,c);
			}
		}
		if(old_y2!=my2) {
			for(i=mx1; i<=mx2; i++) {
				gdImageSetPixel(im,i,my2,c);
			}
		}
		old_y2 = my2;
	}
}

BGD_DECLARE(void) gdImageFillToBorder (gdImagePtr im, int x, int y, int border, int color)
{
	int lastBorder;
	/* Seek left */
	int leftLimit, rightLimit;
	int i;
	int restoreAlphaBleding;

	if (border < 0) {
		/* Refuse to fill to a non-solid border */
		return;
	}

	leftLimit = (-1);

	restoreAlphaBleding = im->alphaBlendingFlag;
	im->alphaBlendingFlag = 0;

	if (x >= im->sx) {
		x = im->sx - 1;
	} else if (x < 0) {
		x = 0;
	}
	if (y >= im->sy) {
		y = im->sy - 1;
	} else if (y < 0) {
		y = 0;
	}
	
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1928,10 +1928,16 @@
 	int i;
 	int restoreAlphaBleding;
 
-	if (border < 0) {
+	if (border < 0 || color < 0) {
 		/* Refuse to fill to a non-solid border */
 		return;
 	}
+
+	if (!im->trueColor) {
+		if ((color > (im->colorsTotal - 1)) || (border > (im->colorsTotal - 1))) {
+			return;
+		}
+    }
 
 	leftLimit = (-1);
 
```
