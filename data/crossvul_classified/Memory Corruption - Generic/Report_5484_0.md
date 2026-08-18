# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5484_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5484_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 319-359 of the vulnerable file.

  iris_info.magic=ReadBlobMSBShort(image);
  do
  {
    /*
      Verify SGI identifier.
    */
    if (iris_info.magic != 0x01DA)
      ThrowReaderException(CorruptImageError,"ImproperImageHeader");
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
    count=ReadBlob(image,sizeof(iris_info.name),(unsigned char *)
      iris_info.name);
    if ((size_t) count != sizeof(iris_info.name))
      ThrowReaderException(CorruptImageError,"ImproperImageHeader");
    iris_info.name[sizeof(iris_info.name)-1]='\0';
    if (*iris_info.name != '\0')
      (void) SetImageProperty(image,"label",iris_info.name,exception);
    iris_info.pixel_format=ReadBlobMSBLong(image);
    if (iris_info.pixel_format != 0)
      ThrowReaderException(CorruptImageError,"ImproperImageHeader");
    count=ReadBlob(image,sizeof(iris_info.filler),iris_info.filler);
    if ((size_t) count != sizeof(iris_info.filler))
      ThrowReaderException(CorruptImageError,"ImproperImageHeader");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -336,6 +336,8 @@
     if ((iris_info.bytes_per_pixel == 0) || (iris_info.bytes_per_pixel > 2))
       ThrowReaderException(CorruptImageError,"ImproperImageHeader");
     iris_info.dimension=ReadBlobMSBShort(image);
+    if ((iris_info.dimension == 0) || (iris_info.dimension > 3)) 
+      ThrowReaderException(CorruptImageError,"ImproperImageHeader");
     iris_info.columns=ReadBlobMSBShort(image);
     iris_info.rows=ReadBlobMSBShort(image);
     iris_info.depth=ReadBlobMSBShort(image);
```
