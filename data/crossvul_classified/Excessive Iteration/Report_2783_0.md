# CrossVul Fix Pair: Excessive Iteration in c
**Pair ID:** 2783_0
**Vulnerability Class:** Excessive Iteration
**CWE:** CWE-834
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2783_0`)

## Vulnerability Information & PoC

## Description
Excessive Iteration - If the iteration can be influenced by an attacker, this weakness could allow attackers to consume excessive resources such as CPU or memory.

## Vulnerable Code
```c
Lines 1311-1354 of the vulnerable file.


  MagickBooleanType
    status;

  channel_image=image;
  mask=(Image *) NULL;
  if ((layer_info->channel_info[channel].type < -1) &&
      (layer_info->mask.page.width > 0) && (layer_info->mask.page.height > 0))
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
      if (mask != (Image *) NULL)
        {
          SetImageType(mask,GrayscaleType,exception);
          channel_image=mask;
        }
    }

  offset=TellBlob(image);
  status=MagickFalse;
  switch(compression)
  {
    case Raw:
      status=ReadPSDChannelRaw(channel_image,psd_info->channels,
        layer_info->channel_info[channel].type,exception);
      break;
    case RLE:
      {
        MagickOffsetType
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1328,10 +1328,10 @@
       if ((layer_info->channel_info[channel].type != -2) ||
           (layer_info->mask.flags > 2) || ((layer_info->mask.flags & 0x02) &&
            (IsStringTrue(option) == MagickFalse)))
-      {
-        SeekBlob(image,layer_info->channel_info[channel].size-2,SEEK_CUR);
-        return(MagickTrue);
-      }
+        {
+          SeekBlob(image,layer_info->channel_info[channel].size-2,SEEK_CUR);
+          return(MagickTrue);
+        }
       mask=CloneImage(image,layer_info->mask.page.width,
         layer_info->mask.page.height,MagickFalse,exception);
       if (mask != (Image *) NULL)
@@ -1706,24 +1706,12 @@
                   (void) LogMagickEvent(CoderEvent,GetMagickModule(),
                     "      layer blending ranges: length=%.20g",(double)
                     ((MagickOffsetType) length));
-                /*
-                  We read it, but don't use it...
-                */
-                for (j=0; j < (ssize_t) length; j+=8)
-                {
-                  size_t blend_source=ReadBlobLong(image);
-                  size_t blend_dest=ReadBlobLong(image);
-                  if (EOFBlob(image) != MagickFalse)
-                    {
-                      layer_info=DestroyLayerInfo(layer_info,number_layers);
-                      ThrowBinaryException(CorruptImageError,
-                        "InsufficientImageDataInFile",image->filename);
-                    }
-                  if (image->debug != MagickFalse)
-                    (void) LogMagickEvent(CoderEvent,GetMagickModule(),
-                      "        source(%x), dest(%x)",(unsigned int)
-                      blend_source,(unsigned int) blend_dest);
-                }
+                if (DiscardBlobBytes(image,length) == MagickFalse)
+                  {
+                    layer_info=DestroyLayerInfo(layer_info,number_layers);
+                    ThrowBinaryException(CorruptImageError,
+                      "UnexpectedEndOfFile",image->filename);
+                  }
               }
             /*
               Layer name.
```
