# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 5324_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5324_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 182-222 of the vulnerable file.

{
	uint8_t *argb;
	int x, y;
	uint8_t *p;
	uint8_t *out;
	size_t out_size;

	if (im == NULL) {
		return;
	}

	if (!gdImageTrueColor(im)) {
		gd_error("Paletter image not supported by webp");
		return;
	}

	if (quality == -1) {
		quality = 80;
	}

	argb = (uint8_t *)gdMalloc(gdImageSX(im) * 4 * gdImageSY(im));
	if (!argb) {
		return;
	}
	p = argb;
	for (y = 0; y < gdImageSY(im); y++) {
		for (x = 0; x < gdImageSX(im); x++) {
			register int c;
			register char a;
			c = im->tpixels[y][x];
			a = gdTrueColorGetAlpha(c);
			if (a == 127) {
				a = 0;
			} else {
				a = 255 - ((a << 1) + (a >> 6));
			}
			*(p++) = gdTrueColorGetRed(c);
			*(p++) = gdTrueColorGetGreen(c);
			*(p++) = gdTrueColorGetBlue(c); 
			*(p++) = a;
		}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -197,6 +197,14 @@
 
 	if (quality == -1) {
 		quality = 80;
+	}
+
+	if (overflow2(gdImageSX(im), 4)) {
+		return;
+	}
+
+	if (overflow2(gdImageSX(im) * 4, gdImageSY(im))) {
+		return;
 	}
 
 	argb = (uint8_t *)gdMalloc(gdImageSX(im) * 4 * gdImageSY(im));
```
