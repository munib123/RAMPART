# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 815_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `815_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 714-754 of the vulnerable file.

      */
      if (cin.file.user_length > GetBlobSize(image))
        ThrowReaderException(CorruptImageError,"InsufficientImageDataInFile");
      profile=BlobToStringInfo((const unsigned char *) NULL,
        cin.file.user_length);
      if (profile == (StringInfo *) NULL)
        ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
      offset+=ReadBlob(image,GetStringInfoLength(profile),
        GetStringInfoDatum(profile));
      (void) SetImageProfile(image,"dpx:user.data",profile,exception);
      profile=DestroyStringInfo(profile);
    }
  image->depth=cin.image.channel[0].bits_per_pixel;
  image->columns=cin.image.channel[0].pixels_per_line;
  image->rows=cin.image.channel[0].lines_per_image;
  if (image_info->ping != MagickFalse)
    {
      (void) CloseBlob(image);
      return(image);
    }
  for ( ; offset < (MagickOffsetType) cin.file.image_offset; offset++)
  {
    int
      c;

    c=ReadBlobByte(image);
    if (c == EOF)
      break;
  }
  if (offset < (MagickOffsetType) cin.file.image_offset)
    ThrowReaderException(CorruptImageError,"ImproperImageHeader");
  status=SetImageExtent(image,image->columns,image->rows,exception);
  if (status == MagickFalse)
    return(DestroyImageList(image));
  (void) SetImageBackgroundColor(image,exception);
  /*
    Convert CIN raster image to pixel packets.
  */
  quantum_info=AcquireQuantumInfo(image_info,image);
  if (quantum_info == (QuantumInfo *) NULL)
    ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -731,6 +731,8 @@
       (void) CloseBlob(image);
       return(image);
     }
+  if (((MagickSizeType) image->columns*image->rows) > GetBlobSize(image))
+    ThrowReaderException(CorruptImageError,"InsufficientImageDataInFile");
   for ( ; offset < (MagickOffsetType) cin.file.image_offset; offset++)
   {
     int
```
