# CrossVul Fix Pair: Double Free in c
**Pair ID:** 848_0
**Vulnerability Class:** Double Free
**CWE:** CWE-415
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `848_0`)

## Vulnerability Information & PoC

## Description
Double Free - When a program calls free() twice with the same argument, the program's memory management data structures become corrupted.

## Vulnerable Code
```c
Lines 39-80 of the vulnerable file.

					if (widthOverflow > 0 || heightOverflow > 0) {
						gifFilePtr->SWidth += widthOverflow;
						gifFilePtr->SHeight += heightOverflow;
					}
					SavedImage *sp = &gifFilePtr->SavedImages[gifFilePtr->ImageCount - 1];
					int_fast32_t topOverflow = gifFilePtr->Image.Top + gifFilePtr->Image.Height - gifFilePtr->SHeight;
					if (topOverflow > 0) {
						sp->ImageDesc.Top -= topOverflow;
					}

					int_fast32_t leftOverflow = gifFilePtr->Image.Left + gifFilePtr->Image.Width - gifFilePtr->SWidth;
					if (leftOverflow > 0) {
						sp->ImageDesc.Left -= leftOverflow;
					}
					if (!updateGCB(info, &lastAllocatedGCBIndex)) {
						break;
					}
				}

				if (decode) {
					int_fast32_t widthOverflow = gifFilePtr->Image.Width - info->originalWidth;
					int_fast32_t heightOverflow = gifFilePtr->Image.Height - info->originalHeight;
					const uint_fast32_t newRasterSize = gifFilePtr->Image.Width * gifFilePtr->Image.Height;
					if (newRasterSize > info->rasterSize || widthOverflow > 0 || heightOverflow > 0) {
						void *tmpRasterBits = reallocarray(info->rasterBits, newRasterSize, sizeof(GifPixelType));
						if (tmpRasterBits == NULL) {
							gifFilePtr->Error = D_GIF_ERR_NOT_ENOUGH_MEM;
							break;
						}
						info->rasterBits = tmpRasterBits;
						info->rasterSize = newRasterSize;
					}
					if (gifFilePtr->Image.Interlace) {
						uint_fast16_t i, j;
						/*
						 * The way an interlaced image should be read -
						 * offsets and jumps...
						 */
						uint_fast8_t InterlacedOffset[] = {0, 4, 2, 1};
						uint_fast8_t InterlacedJumps[] = {8, 8, 4, 2};
						/* Need to perform 4 passes on the image */
						for (i = 0; i < 4; i++)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -56,9 +56,15 @@
 				}
 
 				if (decode) {
-					int_fast32_t widthOverflow = gifFilePtr->Image.Width - info->originalWidth;
-					int_fast32_t heightOverflow = gifFilePtr->Image.Height - info->originalHeight;
 					const uint_fast32_t newRasterSize = gifFilePtr->Image.Width * gifFilePtr->Image.Height;
+					if (newRasterSize == 0) {
+						free(info->rasterBits);
+						info->rasterBits = NULL;
+						info->rasterSize = newRasterSize;
+						return;
+					}
+					const int_fast32_t widthOverflow = gifFilePtr->Image.Width - info->originalWidth;
+					const int_fast32_t heightOverflow = gifFilePtr->Image.Height - info->originalHeight;
 					if (newRasterSize > info->rasterSize || widthOverflow > 0 || heightOverflow > 0) {
 						void *tmpRasterBits = reallocarray(info->rasterBits, newRasterSize, sizeof(GifPixelType));
 						if (tmpRasterBits == NULL) {
```
