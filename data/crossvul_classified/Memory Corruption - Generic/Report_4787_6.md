# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 4787_6
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4787_6`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 704-744 of the vulnerable file.

    {
      StringInfo
        *profile;

      /*
        User defined data.
      */
      profile=BlobToStringInfo((const void *) NULL,cin.file.user_length);
      if (profile == (StringInfo *) NULL)
        ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
      offset+=ReadBlob(image,GetStringInfoLength(profile),
        GetStringInfoDatum(profile));
      (void) SetImageProfile(image,"dpx:user.data",profile);
      profile=DestroyStringInfo(profile);
    }
  for ( ; offset < (MagickOffsetType) cin.file.image_offset; offset++)
    (void) ReadBlobByte(image);
  image->depth=cin.image.channel[0].bits_per_pixel;
  image->columns=cin.image.channel[0].pixels_per_line;
  image->rows=cin.image.channel[0].lines_per_image;
  if (image_info->ping)
    {
      (void) CloseBlob(image);
      return(image);
    }
  /*
    Convert CIN raster image to pixel packets.
  */
  quantum_info=AcquireQuantumInfo(image_info,image);
  if (quantum_info == (QuantumInfo *) NULL)
    ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
  quantum_info->quantum=32;
  quantum_info->pack=MagickFalse;
  quantum_type=RGBQuantum;
  pixels=GetQuantumPixels(quantum_info);
  length=GetQuantumExtent(image,quantum_info,quantum_type);
  length=GetBytesPerRow(image->columns,3,image->depth,MagickTrue);
  if (cin.image.number_channels == 1)
    {
      quantum_type=GrayQuantum;
      length=GetBytesPerRow(image->columns,1,image->depth,MagickTrue);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -721,10 +721,16 @@
   image->depth=cin.image.channel[0].bits_per_pixel;
   image->columns=cin.image.channel[0].pixels_per_line;
   image->rows=cin.image.channel[0].lines_per_image;
-  if (image_info->ping)
+  if (image_info->ping != MagickFalse)
     {
       (void) CloseBlob(image);
       return(image);
+    }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
     }
   /*
     Convert CIN raster image to pixel packets.
```
