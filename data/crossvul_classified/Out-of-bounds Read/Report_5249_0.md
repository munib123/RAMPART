# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 5249_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5249_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 327-367 of the vulnerable file.

    iris_info.storage=(unsigned char) ReadBlobByte(image);
    switch (iris_info.storage)
    {
      case 0x00: image->compression=NoCompression; break;
      case 0x01: image->compression=RLECompression; break;
      default:
        ThrowReaderException(CorruptImageError,"ImproperImageHeader");
    }
    iris_info.bytes_per_pixel=(unsigned char) ReadBlobByte(image);
    if ((iris_info.bytes_per_pixel == 0) || (iris_info.bytes_per_pixel > 2))
      ThrowReaderException(CorruptImageError,"ImproperImageHeader");
    iris_info.dimension=ReadBlobMSBShort(image);
    iris_info.columns=ReadBlobMSBShort(image);
    iris_info.rows=ReadBlobMSBShort(image);
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
      image->depth=(size_t) MagickMin((size_t) 8*iris_info.bytes_per_pixel,
        MAGICKCORE_QUANTUM_DEPTH);
    if (iris_info.depth < 3)
      {
        image->storage_class=PseudoClass;
        image->colors=iris_info.bytes_per_pixel > 1 ? 65535 : 256;
      }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -344,8 +344,10 @@
     iris_info.minimum_value=ReadBlobMSBLong(image);
     iris_info.maximum_value=ReadBlobMSBLong(image);
     iris_info.sans=ReadBlobMSBLong(image);
-    (void) ReadBlob(image,sizeof(iris_info.name),(unsigned char *)
+    count=ReadBlob(image,sizeof(iris_info.name),(unsigned char *)
       iris_info.name);
+    if (count != sizeof(iris_info.name))
+      ThrowReaderException(CorruptImageError,"ImproperImageHeader");
     iris_info.name[sizeof(iris_info.name)-1]='\0';
     if (*iris_info.name != '\0')
       (void) SetImageProperty(image,"label",iris_info.name,exception);
@@ -353,7 +355,8 @@
     if (iris_info.pixel_format != 0)
       ThrowReaderException(CorruptImageError,"ImproperImageHeader");
     count=ReadBlob(image,sizeof(iris_info.filler),iris_info.filler);
-    (void) count;
+    if (count != sizeof(iris_info.filler))
+      ThrowReaderException(CorruptImageError,"ImproperImageHeader");
     image->columns=iris_info.columns;
     image->rows=iris_info.rows;
     image->depth=(size_t) MagickMin(iris_info.depth,MAGICKCORE_QUANTUM_DEPTH);
@@ -365,9 +368,7 @@
         image->storage_class=PseudoClass;
         image->colors=iris_info.bytes_per_pixel > 1 ? 65535 : 256;
       }
-    if (EOFBlob(image) != MagickFalse)
-      ThrowReaderException(CorruptImageError,"ImproperImageHeader");
-    if ((image_info->ping != MagickFalse)  && (image_info->number_scenes != 0))
+    if ((image_info->ping != MagickFalse) && (image_info->number_scenes != 0))
       if (image->scene >= (image_info->scene+image_info->number_scenes-1))
         break;
     status=SetImageExtent(image,image->columns,image->rows,exception);
```
