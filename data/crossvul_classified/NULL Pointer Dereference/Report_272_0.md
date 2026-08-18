# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 272_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `272_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 2848-2895 of the vulnerable file.

		for (i = 0; i < gdMaxColors; i++) {
			dst->red[i]   = src->red[i];
			dst->green[i] = src->green[i];
			dst->blue[i]  = src->blue[i];
			dst->alpha[i] = src->alpha[i];
			dst->open[i]  = src->open[i];
		}
		for (i = 0; i < src->sy; i++) {
			for (x = 0; x < src->sx; x++) {
				dst->pixels[i][x] = src->pixels[i][x];
			}
		}
	} else {
		for (i = 0; i < src->sy; i++) {
			for (x = 0; x < src->sx; x++) {
				dst->tpixels[i][x] = src->tpixels[i][x];
			}
		}
	}

	if (src->styleLength > 0) {
		dst->styleLength = src->styleLength;
		dst->stylePos    = src->stylePos;
		for (i = 0; i < src->styleLength; i++) {
			dst->style[i] = src->style[i];
		}
	}

	dst->interlace   = src->interlace;

	dst->alphaBlendingFlag = src->alphaBlendingFlag;
	dst->saveAlphaFlag     = src->saveAlphaFlag;
	dst->AA                = src->AA;
	dst->AA_color          = src->AA_color;
	dst->AA_dont_blend     = src->AA_dont_blend;

	dst->cx1 = src->cx1;
	dst->cy1 = src->cy1;
	dst->cx2 = src->cx2;
	dst->cy2 = src->cy2;

	dst->res_x = src->res_x;
	dst->res_y = src->res_y;

	dst->paletteQuantizationMethod     = src->paletteQuantizationMethod;
	dst->paletteQuantizationSpeed      = src->paletteQuantizationSpeed;
	dst->paletteQuantizationMinQuality = src->paletteQuantizationMinQuality;
	dst->paletteQuantizationMinQuality = src->paletteQuantizationMinQuality;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2865,14 +2865,6 @@
 		}
 	}
 
-	if (src->styleLength > 0) {
-		dst->styleLength = src->styleLength;
-		dst->stylePos    = src->stylePos;
-		for (i = 0; i < src->styleLength; i++) {
-			dst->style[i] = src->style[i];
-		}
-	}
-
 	dst->interlace   = src->interlace;
 
 	dst->alphaBlendingFlag = src->alphaBlendingFlag;
@@ -2907,6 +2899,7 @@
 
 	if (src->style) {
 		gdImageSetStyle(dst, src->style, src->styleLength);
+		dst->stylePos = src->stylePos;
 	}
 
 	for (i = 0; i < gdMaxColors; i++) {
```
