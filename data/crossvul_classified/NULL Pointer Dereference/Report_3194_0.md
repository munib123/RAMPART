# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 3194_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3194_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 1270-1311 of the vulnerable file.

  channel_image=image;
  mask=(Image *) NULL;
  if (layer_info->channel_info[channel].type < -1)
    {
      const char
        *option;
      /*
        Ignore mask that is not a user supplied layer mask, if the mask is
        disabled or if the flags have unsupported values.
      */
      option=GetImageOption(image_info,"psd:preserve-opacity-mask");
      if ((layer_info->channel_info[channel].type != -2) ||
          (layer_info->mask.flags > 2) || ((layer_info->mask.flags & 0x02) &&
           (IsStringTrue(option) == MagickFalse)))
      {
        SeekBlob(image,layer_info->channel_info[channel].size-2,SEEK_CUR);
        return(MagickTrue);
      }
      mask=CloneImage(image,layer_info->mask.page.width,
        layer_info->mask.page.height,MagickFalse,exception);
      mask->matte=MagickFalse;
      channel_image=mask;
    }

  offset=TellBlob(image);
  status=MagickTrue;
  switch(compression)
  {
    case Raw:
      status=ReadPSDChannelRaw(channel_image,psd_info->channels,
        layer_info->channel_info[channel].type,exception);
      break;
    case RLE:
      {
        MagickOffsetType
          *sizes;

        sizes=ReadPSDRLESizes(channel_image,psd_info,channel_image->rows);
        if (sizes == (MagickOffsetType *) NULL)
          ThrowBinaryException(ResourceLimitError,"MemoryAllocationFailed",
            image->filename);
        status=ReadPSDChannelRLE(channel_image,psd_info,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1287,8 +1287,11 @@
       }
       mask=CloneImage(image,layer_info->mask.page.width,
         layer_info->mask.page.height,MagickFalse,exception);
-      mask->matte=MagickFalse;
-      channel_image=mask;
+      if (mask != (Image *) NULL)
+        {
+          mask->matte=MagickFalse;
+          channel_image=mask;
+        }
     }
 
   offset=TellBlob(image);
```
