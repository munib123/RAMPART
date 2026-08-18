# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 1854_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1854_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 397-438 of the vulnerable file.

      }
      default:
        ThrowReaderException(CoderError,"ColormapTypeNotSupported");
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
    bytes_per_line=sun_info.width*sun_info.depth;
    sun_data=(unsigned char *) AcquireQuantumMemory((size_t) MagickMax(
      sun_info.length,bytes_per_line*sun_info.width),sizeof(*sun_data));
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
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -414,8 +414,8 @@
         sun_info.length || !sun_info.length)
       ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
     number_pixels=(MagickSizeType) image->columns*image->rows;
-    if ((sun_info.type != RT_ENCODED) && (sun_info.depth >= 8) &&
-        ((number_pixels*((sun_info.depth+7)/8)) > sun_info.length))
+    if ((sun_info.type != RT_ENCODED) && 
+        ((number_pixels*sun_info.depth) > (8*sun_info.length)))
       ThrowReaderException(CorruptImageError,"ImproperImageHeader");
     bytes_per_line=sun_info.width*sun_info.depth;
     sun_data=(unsigned char *) AcquireQuantumMemory((size_t) MagickMax(
@@ -537,7 +537,7 @@
             bytes_per_pixel++;
           if (bytes_per_line == 0)
             bytes_per_line=bytes_per_pixel*image->columns;
-          length=image->rows*(bytes_per_line+image->columns % 2);
+          length=image->rows*(bytes_per_line+bytes_per_line % 2);
           if (((sun_info.type == RT_ENCODED) &&
                (length > (bytes_per_line*image->rows))) ||
               ((sun_info.type != RT_ENCODED) && (length > sun_info.length)))
```
