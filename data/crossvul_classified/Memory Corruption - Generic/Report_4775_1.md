# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 4775_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4775_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 164-204 of the vulnerable file.


  register ssize_t
    x;

  register PixelPacket
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
    number_planes_filled,
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
  assert(image_info->signature == MagickSignature);
  if (image_info->debug != MagickFalse)
    (void) LogMagickEvent(TraceEvent,GetMagickModule(),"%s",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -181,11 +181,11 @@
     number_planes,
     number_planes_filled,
     one,
-    offset,
     pixel_info_length;
 
   ssize_t
     count,
+    offset,
     y;
 
   unsigned char
@@ -398,7 +398,8 @@
           offset=((image->rows-y-1)*image->columns*number_planes)+x*
             number_planes+plane;
           operand++;
-          if (offset+((size_t) operand*number_planes) > pixel_info_length)
+          if ((offset < 0) ||
+              (offset+((size_t) operand*number_planes) > pixel_info_length))
             {
               if (number_colormaps != 0)
                 colormap=(unsigned char *) RelinquishMagickMemory(colormap);
@@ -429,14 +430,15 @@
           operand++;
           offset=((image->rows-y-1)*image->columns*number_planes)+x*
             number_planes+plane;
-          p=pixels+offset;
-          if (offset+((size_t) operand*number_planes) > pixel_info_length)
+          if ((offset < 0) ||
+              (offset+((size_t) operand*number_planes) > pixel_info_length))
             {
               if (number_colormaps != 0)
                 colormap=(unsigned char *) RelinquishMagickMemory(colormap);
               pixel_info=RelinquishVirtualMemory(pixel_info);
               ThrowReaderException(CorruptImageError,"UnableToReadImageData");
             }
+          p=pixels+offset;
           for (i=0; i < (ssize_t) operand; i++)
           {
             if ((y < (ssize_t) image->rows) &&
```
