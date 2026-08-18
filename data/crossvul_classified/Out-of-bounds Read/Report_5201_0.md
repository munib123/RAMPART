# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 5201_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5201_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 82-122 of the vulnerable file.

		free_tga( tga );
		return NULL;
	}

	/*!	\brief Populate GD image object
	 *  Copy the pixel data from our tga bitmap buffer into the GD image
	 *  Disable blending and save the alpha channel per default
	 */
	if (tga->alphabits) {
		gdImageAlphaBlending(image, 0);
		gdImageSaveAlpha(image, 1);
	}

	/* TODO: use alphabits as soon as we support 24bit and other alpha bps (ie != 8bits) */
	for (y = 0; y < tga->height; y++) {
		register int *tpix = image->tpixels[y];
		for ( x = 0; x < tga->width; x++, tpix++) {
			if (tga->bits == TGA_BPP_24) {
				*tpix = gdTrueColor(tga->bitmap[bitmap_caret + 2], tga->bitmap[bitmap_caret + 1], tga->bitmap[bitmap_caret]);
				bitmap_caret += 3;
			} else if (tga->bits == TGA_BPP_32 || tga->alphabits) {
				register int a = tga->bitmap[bitmap_caret + 3];

				*tpix = gdTrueColorAlpha(tga->bitmap[bitmap_caret + 2], tga->bitmap[bitmap_caret + 1], tga->bitmap[bitmap_caret], gdAlphaMax - (a >> 1));
				bitmap_caret += 4;
			}
		}
	}

	if (tga->flipv && tga->fliph) {
		gdImageFlipBoth(image);
	} else if (tga->flipv) {
		gdImageFlipVertical(image);
	} else if (tga->fliph) {
		gdImageFlipHorizontal(image);
	}

	free_tga(tga);

	return image;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -99,7 +99,7 @@
 			if (tga->bits == TGA_BPP_24) {
 				*tpix = gdTrueColor(tga->bitmap[bitmap_caret + 2], tga->bitmap[bitmap_caret + 1], tga->bitmap[bitmap_caret]);
 				bitmap_caret += 3;
-			} else if (tga->bits == TGA_BPP_32 || tga->alphabits) {
+			} else if (tga->bits == TGA_BPP_32 && tga->alphabits) {
 				register int a = tga->bitmap[bitmap_caret + 3];
 
 				*tpix = gdTrueColorAlpha(tga->bitmap[bitmap_caret + 2], tga->bitmap[bitmap_caret + 1], tga->bitmap[bitmap_caret], gdAlphaMax - (a >> 1));
@@ -159,16 +159,12 @@
 	printf("wxh: %i %i\n", tga->width, tga->height);
 #endif
 
-	switch(tga->bits) {
-	case 8:
-	case 16:
-	case 24:
-	case 32:
-		break;
-	default:
-		gd_error("bps %i not supported", tga->bits);
-		return -1;
-		break;
+	if (!((tga->bits == TGA_BPP_24 && tga->alphabits == 0)
+		|| (tga->bits == TGA_BPP_32 && tga->alphabits == 8)))
+	{
+		gd_error_ex(GD_WARNING, "gd-tga: %u bits per pixel with %u alpha bits not supported\n",
+			tga->bits, tga->alphabits);
+		return -1;
 	}
 
 	tga->ident = NULL;
```
