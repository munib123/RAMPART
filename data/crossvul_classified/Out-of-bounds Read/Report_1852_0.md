# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 1852_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1852_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 396-436 of the vulnerable file.

        sun_colormap=(unsigned char *) RelinquishMagickMemory(sun_colormap);
        break;
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
    if ((sun_info.type != RT_ENCODED) && 
        ((number_pixels*sun_info.depth) > (8*sun_info.length)))
      ThrowReaderException(CorruptImageError,"ImproperImageHeader");
    bytes_per_line=sun_info.width*sun_info.depth;
    sun_data=(unsigned char *) AcquireQuantumMemory((size_t) MagickMax(
      sun_info.length,bytes_per_line*sun_info.width),sizeof(*sun_data));
    if (sun_data == (unsigned char *) NULL)
      ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
    count=(ssize_t) ReadBlob(image,sun_info.length,sun_data);
    if (count != (ssize_t) sun_info.length)
      ThrowReaderException(CorruptImageError,"UnableToReadImageData");
    height=sun_info.height;
    if ((height == 0) || (sun_info.width == 0) || (sun_info.depth == 0) ||
        ((bytes_per_line/sun_info.depth) != sun_info.width))
      ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
    bytes_per_line+=15;
    bytes_per_line<<=1;
    if ((bytes_per_line >> 1) != (sun_info.width*sun_info.depth+15))
      ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -413,7 +413,7 @@
       return(DestroyImageList(image));
     if ((sun_info.length*sizeof(*sun_data))/sizeof(*sun_data) !=
         sun_info.length || !sun_info.length)
-      ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
+      ThrowReaderException(ResourceLimitError,"ImproperImageHeader");
     number_pixels=(MagickSizeType) image->columns*image->rows;
     if ((sun_info.type != RT_ENCODED) && 
         ((number_pixels*sun_info.depth) > (8*sun_info.length)))
@@ -429,11 +429,11 @@
     height=sun_info.height;
     if ((height == 0) || (sun_info.width == 0) || (sun_info.depth == 0) ||
         ((bytes_per_line/sun_info.depth) != sun_info.width))
-      ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
+      ThrowReaderException(ResourceLimitError,"ImproperImageHeader");
     bytes_per_line+=15;
     bytes_per_line<<=1;
     if ((bytes_per_line >> 1) != (sun_info.width*sun_info.depth+15))
-      ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
+      ThrowReaderException(ResourceLimitError,"ImproperImageHeader");
     bytes_per_line>>=4;
     sun_pixels=(unsigned char *) AcquireQuantumMemory(height,
       bytes_per_line*sizeof(*sun_pixels));
@@ -442,6 +442,12 @@
     if (sun_info.type == RT_ENCODED)
       (void) DecodeImage(sun_data,sun_info.length,sun_pixels,bytes_per_line*
         height);
+    else
+      {
+        if (sun_info.length > (height*bytes_per_line))
+          ThrowReaderException(ResourceLimitError,"ImproperImageHeader");
+        (void) CopyMagickMemory(sun_pixels,sun_data,sun_info.length);
+      }
     sun_data=(unsigned char *) RelinquishMagickMemory(sun_data);
     /*
       Convert SUN raster image to pixel packets.
```
