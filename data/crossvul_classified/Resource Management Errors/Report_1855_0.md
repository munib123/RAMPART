# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 1855_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1855_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 2420-2461 of the vulnerable file.

  */
  if (EOFBlob(image) != MagickFalse)
    {
      ThrowFileException(exception,CorruptImageError,"UnexpectedEndOfFile",
        image->filename);
      return(MagickFalse);
    }
  if (dds_info->ddscaps1 & DDSCAPS_MIPMAP
      && (dds_info->ddscaps1 & DDSCAPS_TEXTURE
          || dds_info->ddscaps2 & DDSCAPS2_CUBEMAP))
    {
      w = DIV2(dds_info->width);
      h = DIV2(dds_info->height);

      /*
        Mipmapcount includes the main image, so start from one
      */
      for (i=1; (i < (ssize_t) dds_info->mipmapcount) && w && h; i++)
      {
        offset = (MagickOffsetType) w * h * pixel_size;
        (void) SeekBlob(image, offset, SEEK_CUR);

        w = DIV2(w);
        h = DIV2(h);
      }
    }
  return(MagickTrue);
}

/*
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%                                                                             %
%                                                                             %
%                                                                             %
%   U n r e g i s t e r D D S I m a g e                                       %
%                                                                             %
%                                                                             %
%                                                                             %
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%
%  UnregisterDDSImage() removes format registrations made by the
%  DDS module from the list of supported formats.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2437,8 +2437,8 @@
       for (i=1; (i < (ssize_t) dds_info->mipmapcount) && w && h; i++)
       {
         offset = (MagickOffsetType) w * h * pixel_size;
-        (void) SeekBlob(image, offset, SEEK_CUR);
-
+        if (SeekBlob(image,offset,SEEK_CUR) < 0)
+          break;
         w = DIV2(w);
         h = DIV2(h);
       }
```
