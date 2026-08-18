# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 5167_1
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5167_1`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 113-153 of the vulnerable file.

{
	va_list args;

	TSRMLS_FETCH();

	va_start(args, format);
	php_verror(NULL, "", E_WARNING, format, args TSRMLS_CC);
	va_end(args);
}

gdImagePtr gdImageCreate (int sx, int sy)
{
	int i;
	gdImagePtr im;

	if (overflow2(sx, sy)) {
		return NULL;
	}

	if (overflow2(sizeof(unsigned char *), sy)) {
		return NULL;
	}

	im = (gdImage *) gdCalloc(1, sizeof(gdImage));

	/* Row-major ever since gd 1.3 */
	im->pixels = (unsigned char **) gdMalloc(sizeof(unsigned char *) * sy);
	im->AA_opacity = (unsigned char **) gdMalloc(sizeof(unsigned char *) * sy);
	im->polyInts = 0;
	im->polyAllocated = 0;
	im->brush = 0;
	im->tile = 0;
	im->style = 0;
	for (i = 0; i < sy; i++) {
		/* Row-major ever since gd 1.3 */
		im->pixels[i] = (unsigned char *) gdCalloc(sx, sizeof(unsigned char));
		im->AA_opacity[i] = (unsigned char *) gdCalloc(sx, sizeof(unsigned char));
	}
	im->sx = sx;
	im->sy = sy;
	im->colorsTotal = 0;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -133,6 +133,10 @@
 		return NULL;
 	}
 
+	if (overflow2(sizeof(unsigned char *), sx)) {
+		return NULL;
+	}
+
 	im = (gdImage *) gdCalloc(1, sizeof(gdImage));
 
 	/* Row-major ever since gd 1.3 */
@@ -1098,12 +1102,12 @@
 	int thick = im->thick;
 
 	if (color == gdAntiAliased) {
-		/* 
+		/*
 		   gdAntiAliased passed as color: use the much faster, much cheaper
 		   and equally attractive gdImageAALine implementation. That
 		   clips too, so don't clip twice.
 		   */
-		gdImageAALine(im, x1, y1, x2, y2, im->AA_color); 
+		gdImageAALine(im, x1, y1, x2, y2, im->AA_color);
 		return;
 	}
 
@@ -1880,7 +1884,7 @@
 		return;
 	}
 
-	alphablending_bak = im->alphaBlendingFlag;	
+	alphablending_bak = im->alphaBlendingFlag;
 	im->alphaBlendingFlag = 0;
 
 	if (nc==gdTiled){
@@ -1892,7 +1896,7 @@
 	wx2=im->sx;wy2=im->sy;
 	oc = gdImageGetPixel(im, x, y);
 	if (oc==nc || x<0 || x>wx2 || y<0 || y>wy2) {
-		im->alphaBlendingFlag = alphablending_bak;	
+		im->alphaBlendingFlag = alphablending_bak;
 		return;
 	}
 
@@ -1955,7 +1959,7 @@
 	efree(stack);
 
 done:
-	im->alphaBlendingFlag = alphablending_bak;	
+	im->alphaBlendingFlag = alphablending_bak;
 }
 
 static void _gdImageFillTiled(gdImagePtr im, int x, int y, int nc)
@@ -2061,7 +2065,7 @@
 
 		x1ul = x1 - half;
 		y1ul = y1 - half;
-		
+
 		x2lr = x2 + half;
 		y2lr = y2 + half;
 
@@ -2259,7 +2263,7 @@
 	int tox, toy;
 	int ncR, ncG, ncB;
 	toy = dstY;
-	
+
 	for (y = srcY; y < (srcY + h); y++) {
 		tox = dstX;
 		for (x = srcX; x < (srcX + w); x++) {
@@ -2356,7 +2360,7 @@
 	int colorMap[gdMaxColors];
 	/* Stretch vectors */
 	int *stx, *sty;
-	
+
 	if (overflow2(sizeof(int), srcW)) {
 		return;
 	}
@@ -2901,7 +2905,7 @@
     src_weight = gdAlphaTransparent - src_alpha;
     dst_weight = (gdAlphaTransparent - dst_alpha) * src_alpha / gdAlphaMax;
     tot_weight = src_weight + dst_weight;
-    
+
 /* -------------------------------------------------------------------- */
 /*      What red, green and blue result values will we use?             */
 /* -------------------------------------------------------------------- */
```
