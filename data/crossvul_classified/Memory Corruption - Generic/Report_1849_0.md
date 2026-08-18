# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 1849_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1849_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 411-452 of the vulnerable file.

    }
    image->alpha_trait=sun_info.depth == 32 ? BlendPixelTrait :
      UndefinedPixelTrait;
    image->columns=sun_info.width;
    image->rows=sun_info.height;
    if (image_info->ping != MagickFalse)
      {
        (void) CloseBlob(image);
        return(GetFirstImageInList(image));
      }
    status=SetImageExtent(image,image->columns,image->rows,exception);
    if (status == MagickFalse)
      return(DestroyImageList(image));
    if ((sun_info.length*sizeof(*sun_data))/sizeof(*sun_data) !=
        sun_info.length || !sun_info.length)
      ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
    number_pixels=(MagickSizeType) image->columns*image->rows;
    if ((sun_info.type != RT_ENCODED) && (sun_info.depth >= 8) &&
        ((number_pixels*((sun_info.depth+7)/8)) > sun_info.length))
      ThrowReaderException(CorruptImageError,"ImproperImageHeader");
    sun_data=(unsigned char *) AcquireQuantumMemory((size_t) sun_info.length,
      sizeof(*sun_data));
    if (sun_data == (unsigned char *) NULL)
      ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
    count=(ssize_t) ReadBlob(image,sun_info.length,sun_data);
    if (count != (ssize_t) sun_info.length)
      ThrowReaderException(CorruptImageError,"UnableToReadImageData");
    sun_pixels=sun_data;
    bytes_per_line=0;
    if (sun_info.type == RT_ENCODED)
      {
        size_t
          height;

        /*
          Read run-length encoded raster pixels.
        */
        height=sun_info.height;
        bytes_per_line=sun_info.width*sun_info.depth;
        if ((height == 0) || (sun_info.width == 0) || (sun_info.depth == 0) ||
            ((bytes_per_line/sun_info.depth) != sun_info.width))
          ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -428,8 +428,9 @@
     if ((sun_info.type != RT_ENCODED) && (sun_info.depth >= 8) &&
         ((number_pixels*((sun_info.depth+7)/8)) > sun_info.length))
       ThrowReaderException(CorruptImageError,"ImproperImageHeader");
-    sun_data=(unsigned char *) AcquireQuantumMemory((size_t) sun_info.length,
-      sizeof(*sun_data));
+    bytes_per_line=sun_info.width*sun_info.depth;
+    sun_data=(unsigned char *) AcquireQuantumMemory((size_t) MagickMax(
+      sun_info.length,bytes_per_line*sun_info.width),sizeof(*sun_data));
     if (sun_data == (unsigned char *) NULL)
       ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
     count=(ssize_t) ReadBlob(image,sun_info.length,sun_data);
@@ -446,7 +447,6 @@
           Read run-length encoded raster pixels.
         */
         height=sun_info.height;
-        bytes_per_line=sun_info.width*sun_info.depth;
         if ((height == 0) || (sun_info.width == 0) || (sun_info.depth == 0) ||
             ((bytes_per_line/sun_info.depth) != sun_info.width))
           ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
```
