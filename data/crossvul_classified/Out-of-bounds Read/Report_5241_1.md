# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 5241_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5241_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 742-782 of the vulnerable file.

			break;
		}
	} else {
		/* TODO: implement a reader for separate panes. We detect this case earlier for now and use force_rgb */
	}

	gdFree(buffer);
	return GD_SUCCESS;
}

static int createFromTiffRgba(TIFF * tif, gdImagePtr im)
{
	int a;
	int x, y;
	int alphaBlendingFlag = 0;
	int color;
	int width = im->sx;
	int height = im->sy;
	uint32 *buffer;
	uint32 rgba;

	/* switch off colour merging on target gd image just while we write out
	 * content - we want to preserve the alpha data until the user chooses
	 * what to do with the image */
	alphaBlendingFlag = im->alphaBlendingFlag;
	gdImageAlphaBlending(im, 0);

	buffer = (uint32 *) gdCalloc(sizeof(uint32), width * height);
	if (!buffer) {
		return GD_FAILURE;
	}

	TIFFReadRGBAImage(tif, width, height, buffer, 0);

	for(y = 0; y < height; y++) {
		for(x = 0; x < width; x++) {
			/* if it doesn't already exist, allocate a new colour,
			 * else use existing one */
			rgba = buffer[(y * width + x)];
			a = (0xff - TIFFGetA(rgba)) / 2;
			color = gdTrueColorAlpha(TIFFGetR(rgba), TIFFGetG(rgba), TIFFGetB(rgba), a);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -759,6 +759,7 @@
 	int height = im->sy;
 	uint32 *buffer;
 	uint32 rgba;
+	int success;
 
 	/* switch off colour merging on target gd image just while we write out
 	 * content - we want to preserve the alpha data until the user chooses
@@ -771,18 +772,20 @@
 		return GD_FAILURE;
 	}
 
-	TIFFReadRGBAImage(tif, width, height, buffer, 0);
-
-	for(y = 0; y < height; y++) {
-		for(x = 0; x < width; x++) {
-			/* if it doesn't already exist, allocate a new colour,
-			 * else use existing one */
-			rgba = buffer[(y * width + x)];
-			a = (0xff - TIFFGetA(rgba)) / 2;
-			color = gdTrueColorAlpha(TIFFGetR(rgba), TIFFGetG(rgba), TIFFGetB(rgba), a);
-
-			/* set pixel colour to this colour */
-			gdImageSetPixel(im, x, height - y - 1, color);
+	success = TIFFReadRGBAImage(tif, width, height, buffer, 1);
+
+	if (success) {
+		for(y = 0; y < height; y++) {
+			for(x = 0; x < width; x++) {
+				/* if it doesn't already exist, allocate a new colour,
+				 * else use existing one */
+				rgba = buffer[(y * width + x)];
+				a = (0xff - TIFFGetA(rgba)) / 2;
+				color = gdTrueColorAlpha(TIFFGetR(rgba), TIFFGetG(rgba), TIFFGetB(rgba), a);
+	
+				/* set pixel colour to this colour */
+				gdImageSetPixel(im, x, height - y - 1, color);
+			}
 		}
 	}
 
@@ -790,7 +793,7 @@
 
 	/* now reset colour merge for alpha blending routines */
 	gdImageAlphaBlending(im, alphaBlendingFlag);
-	return GD_SUCCESS;
+	return success;
 }
 
 /*
```
