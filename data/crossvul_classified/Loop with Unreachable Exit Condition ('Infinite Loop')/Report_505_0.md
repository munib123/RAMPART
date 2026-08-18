# CrossVul Fix Pair: Loop with Unreachable Exit Condition ('Infinite Loop') in c
**Pair ID:** 505_0
**Vulnerability Class:** Loop with Unreachable Exit Condition ('Infinite Loop')
**CWE:** CWE-835
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `505_0`)

## Vulnerability Information & PoC

## Description
Loop with Unreachable Exit Condition ('Infinite Loop') - If the loop can be influenced by an attacker, this weakness could allow attackers to consume excessive resources such as CPU or memory.

## Vulnerable Code
```c
Lines 651-691 of the vulnerable file.

              "  Geometry: %.20gx%.20g",(double) bmp_info.width,(double)
              bmp_info.height);
          }
      }
    else
      {
        /*
          Microsoft Windows BMP image file.
        */
        if (bmp_info.size < 40)
          ThrowReaderException(CorruptImageError,"NonOS2HeaderSizeError");
        bmp_info.width=(ssize_t) ReadBlobLSBSignedLong(image);
        bmp_info.height=(ssize_t) ReadBlobLSBSignedLong(image);
        bmp_info.planes=ReadBlobLSBShort(image);
        bmp_info.bits_per_pixel=ReadBlobLSBShort(image);
        bmp_info.compression=ReadBlobLSBLong(image);
        bmp_info.image_size=ReadBlobLSBLong(image);
        bmp_info.x_pixels=ReadBlobLSBLong(image);
        bmp_info.y_pixels=ReadBlobLSBLong(image);
        bmp_info.number_colors=ReadBlobLSBLong(image);
        if (bmp_info.number_colors > GetBlobSize(image))
          ThrowReaderException(CorruptImageError,"InsufficientImageDataInFile");
        bmp_info.colors_important=ReadBlobLSBLong(image);
        if (image->debug != MagickFalse)
          {
            (void) LogMagickEvent(CoderEvent,GetMagickModule(),
              "  Format: MS Windows bitmap");
            (void) LogMagickEvent(CoderEvent,GetMagickModule(),
              "  Geometry: %.20gx%.20g",(double) bmp_info.width,(double)
              bmp_info.height);
            (void) LogMagickEvent(CoderEvent,GetMagickModule(),
              "  Bits per pixel: %.20g",(double) bmp_info.bits_per_pixel);
            switch (bmp_info.compression)
            {
              case BI_RGB:
              {
                (void) LogMagickEvent(CoderEvent,GetMagickModule(),
                  "  Compression: BI_RGB");
                break;
              }
              case BI_RLE4:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -668,7 +668,7 @@
         bmp_info.x_pixels=ReadBlobLSBLong(image);
         bmp_info.y_pixels=ReadBlobLSBLong(image);
         bmp_info.number_colors=ReadBlobLSBLong(image);
-        if (bmp_info.number_colors > GetBlobSize(image))
+        if ((MagickSizeType) bmp_info.number_colors > GetBlobSize(image))
           ThrowReaderException(CorruptImageError,"InsufficientImageDataInFile");
         bmp_info.colors_important=ReadBlobLSBLong(image);
         if (image->debug != MagickFalse)
@@ -1452,13 +1452,12 @@
     if (image_info->number_scenes != 0)
       if (image->scene >= (image_info->scene+image_info->number_scenes-1))
         break;
+    offset=(MagickOffsetType) bmp_info.ba_offset;
+    if (offset != 0)
+      if ((offset < TellBlob(image)) ||
+          (SeekBlob(image,offset,SEEK_SET) != offset))
+        ThrowReaderException(CorruptImageError,"ImproperImageHeader");
     *magick='\0';
-    if (bmp_info.ba_offset != 0)
-      {
-        offset=SeekBlob(image,(MagickOffsetType) bmp_info.ba_offset,SEEK_SET);
-        if (offset < 0)
-          ThrowReaderException(CorruptImageError,"ImproperImageHeader");
-      }
     count=ReadBlob(image,2,magick);
     if ((count == 2) && (IsBMP(magick,2) != MagickFalse))
       {
```
