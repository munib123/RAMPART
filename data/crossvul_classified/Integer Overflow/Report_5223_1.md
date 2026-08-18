# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 5223_1
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5223_1`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 1676-1716 of the vulnerable file.

        {
          type=3;
          bmp_info.size=40;
        }
      else
        {
          int
            extra_size;

          bmp_info.size=108;
          extra_size=68;
          if ((image->rendering_intent != UndefinedIntent) ||
              (profile != (StringInfo *) NULL))
            {
              bmp_info.size=124;
              extra_size+=16;
            }
          bmp_info.file_size+=extra_size;
          bmp_info.offset_bits+=extra_size;
        }
    bmp_info.width=(ssize_t) image->columns;
    bmp_info.height=(ssize_t) image->rows;
    bmp_info.planes=1;
    bmp_info.image_size=(unsigned int) (bytes_per_line*image->rows);
    bmp_info.file_size+=bmp_info.image_size;
    bmp_info.x_pixels=75*39;
    bmp_info.y_pixels=75*39;
    switch (image->units)
    {
      case UndefinedResolution:
      case PixelsPerInchResolution:
      {
        bmp_info.x_pixels=(unsigned int) (100.0*image->resolution.x/2.54);
        bmp_info.y_pixels=(unsigned int) (100.0*image->resolution.y/2.54);
        break;
      }
      case PixelsPerCentimeterResolution:
      {
        bmp_info.x_pixels=(unsigned int) (100.0*image->resolution.x);
        bmp_info.y_pixels=(unsigned int) (100.0*image->resolution.y);
        break;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1693,10 +1693,13 @@
           bmp_info.file_size+=extra_size;
           bmp_info.offset_bits+=extra_size;
         }
+    if ((image->columns != (signed int) image->columns) ||
+        (image->rows != (signed int) image->rows))
+      ThrowWriterException(ImageError,"WidthOrHeightExceedsLimit");
     bmp_info.width=(ssize_t) image->columns;
     bmp_info.height=(ssize_t) image->rows;
     bmp_info.planes=1;
-    bmp_info.image_size=(unsigned int) (bytes_per_line*image->rows);
+    bmp_info.image_size=(unsigned long) (bytes_per_line*image->rows);
     bmp_info.file_size+=bmp_info.image_size;
     bmp_info.x_pixels=75*39;
     bmp_info.y_pixels=75*39;
```
