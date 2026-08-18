# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 5297_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5297_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 159-199 of the vulnerable file.

  Quantum
    index;

  register ssize_t
    x;

  register Quantum
    *q;

  register ssize_t
    i;

  register unsigned char
    *p;

  size_t
    bits_per_pixel,
    map_length,
    number_colormaps,
    number_planes,
    one,
    offset,
    pixel_info_length;

  ssize_t
    count,
    y;

  unsigned char
    background_color[256],
    *colormap,
    pixel,
    plane,
    *pixels;

  /*
    Open image file.
  */
  assert(image_info != (const ImageInfo *) NULL);
  assert(image_info->signature == MagickCoreSignature);
  if (image_info->debug != MagickFalse)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -176,6 +176,7 @@
     map_length,
     number_colormaps,
     number_planes,
+    number_planes_filled,
     one,
     offset,
     pixel_info_length;
@@ -311,9 +312,12 @@
     if (image->alpha_trait != UndefinedPixelTrait)
       number_planes++;
     number_pixels=(MagickSizeType) image->columns*image->rows;
-    if ((number_pixels*number_planes) != (size_t) (number_pixels*number_planes))
+    number_planes_filled=(number_planes % 2 == 0) ? number_planes :
+      number_planes+1;
+    if ((number_pixels*number_planes_filled) != (size_t) (number_pixels*
+         number_planes_filled))
       ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
-    pixel_info_length=image->columns*image->rows*MagickMax(number_planes,4);
+    pixel_info_length=image->columns*image->rows*number_planes_filled;
     pixel_info=AcquireVirtualMemory(pixel_info_length,sizeof(*pixels));
     if (pixel_info == (MemoryInfo *) NULL)
       ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
```
