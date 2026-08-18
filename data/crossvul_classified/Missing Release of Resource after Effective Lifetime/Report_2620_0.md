# CrossVul Fix Pair: Missing Release of Resource after Effective Lifetime in c
**Pair ID:** 2620_0
**Vulnerability Class:** Missing Release of Resource after Effective Lifetime
**CWE:** CWE-772
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2620_0`)

## Vulnerability Information & PoC

## Description
Missing Release of Resource after Effective Lifetime - When a resource is not released after use, it can allow attackers to cause a denial of service by causing the allocation of resources without triggering their release.

## Vulnerable Code
```c
Lines 311-351 of the vulnerable file.

  unsigned char
    *blob;

  /*
    Convert image to base64-encoding.
  */
  assert(image_info != (const ImageInfo *) NULL);
  assert(image_info->signature == MagickSignature);
  assert(image != (Image *) NULL);
  assert(image->signature == MagickSignature);
  if (image->debug != MagickFalse)
    (void) LogMagickEvent(TraceEvent,GetMagickModule(),"%s",image->filename);
  exception=(&image->exception);
  write_info=CloneImageInfo(image_info);
  (void) SetImageInfo(write_info,1,exception);
  if (LocaleCompare(write_info->magick,"INLINE") == 0)
    (void) CopyMagickString(write_info->magick,image->magick,MaxTextExtent);
  magick_info=GetMagickInfo(write_info->magick,exception);
  if ((magick_info == (const MagickInfo *) NULL) ||
      (GetMagickMimeType(magick_info) == (const char *) NULL))
    ThrowWriterException(CorruptImageError,"ImageTypeNotSupported");
  (void) CopyMagickString(image->filename,write_info->filename,MaxTextExtent);
  blob_length=2048;
  write_image=CloneImage(image,0,0,MagickTrue,exception);
  if (write_image == (Image *) NULL)
    {
      write_info=DestroyImageInfo(write_info);
      return(MagickTrue);
    }
  blob=(unsigned char *) ImageToBlob(write_info,write_image,&blob_length,
    exception);
  write_image=DestroyImage(write_image);
  write_info=DestroyImageInfo(write_info);
  if (blob == (unsigned char *) NULL)
    return(MagickFalse);
  encode_length=0;
  base64=Base64Encode(blob,blob_length,&encode_length);
  blob=(unsigned char *) RelinquishMagickMemory(blob);
  if (base64 == (char *) NULL)
    ThrowWriterException(ResourceLimitError,"MemoryAllocationFailed");
  /*
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -328,7 +328,10 @@
   magick_info=GetMagickInfo(write_info->magick,exception);
   if ((magick_info == (const MagickInfo *) NULL) ||
       (GetMagickMimeType(magick_info) == (const char *) NULL))
-    ThrowWriterException(CorruptImageError,"ImageTypeNotSupported");
+    {
+      write_info=DestroyImageInfo(write_info);
+      ThrowWriterException(CorruptImageError,"ImageTypeNotSupported");
+    }
   (void) CopyMagickString(image->filename,write_info->filename,MaxTextExtent);
   blob_length=2048;
   write_image=CloneImage(image,0,0,MagickTrue,exception);
```
