# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 5248_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5248_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 341-382 of the vulnerable file.

    iris_info.depth=ReadBlobMSBShort(image);
    if ((iris_info.depth == 0) || (iris_info.depth > 4))
      ThrowReaderException(CorruptImageError,"ImproperImageHeader");
    iris_info.minimum_value=ReadBlobMSBLong(image);
    iris_info.maximum_value=ReadBlobMSBLong(image);
    iris_info.sans=ReadBlobMSBLong(image);
    (void) ReadBlob(image,sizeof(iris_info.name),(unsigned char *)
      iris_info.name);
    iris_info.name[sizeof(iris_info.name)-1]='\0';
    if (*iris_info.name != '\0')
      (void) SetImageProperty(image,"label",iris_info.name,exception);
    iris_info.pixel_format=ReadBlobMSBLong(image);
    if (iris_info.pixel_format != 0)
      ThrowReaderException(CorruptImageError,"ImproperImageHeader");
    count=ReadBlob(image,sizeof(iris_info.filler),iris_info.filler);
    (void) count;
    image->columns=iris_info.columns;
    image->rows=iris_info.rows;
    image->depth=(size_t) MagickMin(iris_info.depth,MAGICKCORE_QUANTUM_DEPTH);
    if (iris_info.pixel_format == 0)
      image->depth=(size_t) MagickMin((size_t) 8*
        iris_info.bytes_per_pixel,MAGICKCORE_QUANTUM_DEPTH);
    if (iris_info.depth < 3)
      {
        image->storage_class=PseudoClass;
        image->colors=iris_info.bytes_per_pixel > 1 ? 65535 : 256;
      }
    if ((image_info->ping != MagickFalse)  && (image_info->number_scenes != 0))
      if (image->scene >= (image_info->scene+image_info->number_scenes-1))
        break;
    status=SetImageExtent(image,image->columns,image->rows,exception);
    if (status == MagickFalse)
      return(DestroyImageList(image));
    /*
      Allocate SGI pixels.
    */
    bytes_per_pixel=(size_t) iris_info.bytes_per_pixel;
    number_pixels=(MagickSizeType) iris_info.columns*iris_info.rows;
    if ((4*bytes_per_pixel*number_pixels) != ((MagickSizeType) (size_t)
        (4*bytes_per_pixel*number_pixels)))
      ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
    pixel_info=AcquireVirtualMemory(iris_info.columns,iris_info.rows*4*
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -358,13 +358,15 @@
     image->rows=iris_info.rows;
     image->depth=(size_t) MagickMin(iris_info.depth,MAGICKCORE_QUANTUM_DEPTH);
     if (iris_info.pixel_format == 0)
-      image->depth=(size_t) MagickMin((size_t) 8*
-        iris_info.bytes_per_pixel,MAGICKCORE_QUANTUM_DEPTH);
+      image->depth=(size_t) MagickMin((size_t) 8*iris_info.bytes_per_pixel,
+        MAGICKCORE_QUANTUM_DEPTH);
     if (iris_info.depth < 3)
       {
         image->storage_class=PseudoClass;
         image->colors=iris_info.bytes_per_pixel > 1 ? 65535 : 256;
       }
+    if (EOFBlob(image) != MagickFalse)
+      ThrowReaderException(CorruptImageError,"ImproperImageHeader");
     if ((image_info->ping != MagickFalse)  && (image_info->number_scenes != 0))
       if (image->scene >= (image_info->scene+image_info->number_scenes-1))
         break;
```
