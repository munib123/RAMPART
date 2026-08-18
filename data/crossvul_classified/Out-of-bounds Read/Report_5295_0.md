# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 5295_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5295_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 2354-2395 of the vulnerable file.


static MagickBooleanType WriteImageChannels(const PSDInfo *psd_info,
  const ImageInfo *image_info,Image *image,Image *next_image,
  const MagickBooleanType separate,ExceptionInfo *exception)
{
  size_t
    channels,
    packet_size;

  unsigned char
    *compact_pixels;

  /*
    Write uncompressed pixels as separate planes.
  */
  channels=1;
  packet_size=next_image->depth > 8UL ? 2UL : 1UL;
  compact_pixels=(unsigned char *) NULL;
  if (next_image->compression == RLECompression)
    {
      compact_pixels=(unsigned char *) AcquireQuantumMemory(2*channels*
        next_image->columns,packet_size*sizeof(*compact_pixels));
      if (compact_pixels == (unsigned char *) NULL)
        ThrowWriterException(ResourceLimitError,"MemoryAllocationFailed");
    }
  if (IsImageGray(next_image) != MagickFalse)
    {
      if (next_image->compression == RLECompression)
        {
          /*
            Packbits compression.
          */
          (void) WriteBlobMSBShort(image,1);
          WritePackbitsLength(psd_info,image_info,image,next_image,
            compact_pixels,GrayQuantum,exception);
          if (next_image->alpha_trait != UndefinedPixelTrait)
            WritePackbitsLength(psd_info,image_info,image,next_image,
              compact_pixels,AlphaQuantum,exception);
        }
      WriteOneChannel(psd_info,image_info,image,next_image,compact_pixels,
        GrayQuantum,MagickTrue,exception);
      if (next_image->alpha_trait != UndefinedPixelTrait)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2371,8 +2371,8 @@
   compact_pixels=(unsigned char *) NULL;
   if (next_image->compression == RLECompression)
     {
-      compact_pixels=(unsigned char *) AcquireQuantumMemory(2*channels*
-        next_image->columns,packet_size*sizeof(*compact_pixels));
+      compact_pixels=(unsigned char *) AcquireQuantumMemory((2*channels*
+        next_image->columns)+1,packet_size*sizeof(*compact_pixels));
       if (compact_pixels == (unsigned char *) NULL)
         ThrowWriterException(ResourceLimitError,"MemoryAllocationFailed");
     }
```
