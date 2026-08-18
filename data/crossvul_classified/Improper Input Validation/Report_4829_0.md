# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 4829_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4829_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 486-529 of the vulnerable file.

					GD2_DBG (printf ("Error reading comproessed chunk\n"));
					goto fail;
				};

				chunkPos = 0;
			};

			for (y = ylo; (y < yhi); y++) {

				xlo = cx * cs;
				xhi = xlo + cs;
				if (xhi > im->sx) {
					xhi = im->sx;
				};
				/*GD2_DBG(printf("y=%d: ",y)); */
				if (!gd2_compressed (fmt)) {
					for (x = xlo; x < xhi; x++) {

						if (im->trueColor) {
							if (!gdGetInt (&im->tpixels[y][x], in)) {
								/*printf("EOF while reading\n"); */
								/*gdImageDestroy(im); */
								/*return 0; */
								im->tpixels[y][x] = 0;
							}
						} else {
							int ch;
							if (!gdGetByte (&ch, in)) {
								/*printf("EOF while reading\n"); */
								/*gdImageDestroy(im); */
								/*return 0; */
								ch = 0;
							}
							im->pixels[y][x] = ch;
						}
					}
				} else {
					for (x = xlo; x < xhi; x++) {
						if (im->trueColor) {
							/* 2.0.1: work around a gcc bug by being verbose.
							   TBB */
							int a = chunkBuf[chunkPos++] << 24;
							int r = chunkBuf[chunkPos++] << 16;
							int g = chunkBuf[chunkPos++] << 8;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -503,18 +503,16 @@
 
 						if (im->trueColor) {
 							if (!gdGetInt (&im->tpixels[y][x], in)) {
-								/*printf("EOF while reading\n"); */
-								/*gdImageDestroy(im); */
-								/*return 0; */
-								im->tpixels[y][x] = 0;
+								gd_error("gd2: EOF while reading\n");
+								gdImageDestroy(im);
+								return NULL;
 							}
 						} else {
 							int ch;
 							if (!gdGetByte (&ch, in)) {
-								/*printf("EOF while reading\n"); */
-								/*gdImageDestroy(im); */
-								/*return 0; */
-								ch = 0;
+								gd_error("gd2: EOF while reading\n");
+								gdImageDestroy(im);
+								return NULL;
 							}
 							im->pixels[y][x] = ch;
 						}
```
