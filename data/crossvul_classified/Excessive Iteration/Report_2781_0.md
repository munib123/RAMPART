# CrossVul Fix Pair: Excessive Iteration in c
**Pair ID:** 2781_0
**Vulnerability Class:** Excessive Iteration
**CWE:** CWE-834
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2781_0`)

## Vulnerability Information & PoC

## Description
Excessive Iteration - If the iteration can be influenced by an attacker, this weakness could allow attackers to consume excessive resources such as CPU or memory.

## Vulnerable Code
```c
Lines 647-687 of the vulnerable file.

            }
          datum[i]=(unsigned char) c;
        }
        SetStringInfoLength(profile,(size_t) i+1);
        (void) SetImageProfile(image,"icc",profile);
        profile=DestroyStringInfo(profile);
        continue;
      }
    if (LocaleNCompare(PhotoshopProfile,command,strlen(PhotoshopProfile)) == 0)
      {
        unsigned char
          *p;

        /*
          Read Photoshop profile.
        */
        count=(ssize_t) sscanf(command,PhotoshopProfile " %lu",&extent);
        if (count != 1)
          continue;
        length=extent;
        profile=BlobToStringInfo((const void *) NULL,length);
        if (profile != (StringInfo *) NULL)
          {
            p=GetStringInfoDatum(profile);
            for (i=0; i < (ssize_t) length; i++)
              *p++=(unsigned char) ProfileInteger(image,hex_digits);
            (void) SetImageProfile(image,"8bim",profile);
            profile=DestroyStringInfo(profile);
          }
        continue;
      }
    if (LocaleNCompare(BeginXMPPacket,command,strlen(BeginXMPPacket)) == 0)
      {
        register size_t
          i;

        /*
          Read XMP profile.
        */
        p=command;
        profile=StringToStringInfo(command);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -664,6 +664,8 @@
         if (count != 1)
           continue;
         length=extent;
+        if (length > GetBlobSize(image))
+          ThrowReaderException(CorruptImageError,"InsufficientImageDataInFile");
         profile=BlobToStringInfo((const void *) NULL,length);
         if (profile != (StringInfo *) NULL)
           {
@@ -1057,6 +1059,7 @@
   entry->decoder=(DecodeImageHandler *) ReadPSImage;
   entry->encoder=(EncodeImageHandler *) WritePSImage;
   entry->magick=(IsImageFormatHandler *) IsPS;
+  entry->seekable_stream=MagickTrue;
   entry->adjoin=MagickFalse;
   entry->blob_support=MagickFalse;
   entry->seekable_stream=MagickTrue;
@@ -1068,6 +1071,7 @@
   entry=SetMagickInfo("EPS");
   entry->decoder=(DecodeImageHandler *) ReadPSImage;
   entry->encoder=(EncodeImageHandler *) WritePSImage;
+  entry->seekable_stream=MagickTrue;
   entry->magick=(IsImageFormatHandler *) IsPS;
   entry->adjoin=MagickFalse;
   entry->blob_support=MagickFalse;
@@ -1079,6 +1083,7 @@
   entry=SetMagickInfo("EPSF");
   entry->decoder=(DecodeImageHandler *) ReadPSImage;
   entry->encoder=(EncodeImageHandler *) WritePSImage;
+  entry->seekable_stream=MagickTrue;
   entry->magick=(IsImageFormatHandler *) IsPS;
   entry->adjoin=MagickFalse;
   entry->blob_support=MagickFalse;
@@ -1090,6 +1095,7 @@
   entry=SetMagickInfo("EPSI");
   entry->decoder=(DecodeImageHandler *) ReadPSImage;
   entry->encoder=(EncodeImageHandler *) WritePSImage;
+  entry->seekable_stream=MagickTrue;
   entry->magick=(IsImageFormatHandler *) IsPS;
   entry->adjoin=MagickFalse;
   entry->blob_support=MagickFalse;
@@ -1102,6 +1108,7 @@
   entry=SetMagickInfo("PS");
   entry->decoder=(DecodeImageHandler *) ReadPSImage;
   entry->encoder=(EncodeImageHandler *) WritePSImage;
+  entry->seekable_stream=MagickTrue;
   entry->magick=(IsImageFormatHandler *) IsPS;
   entry->mime_type=ConstantString("application/postscript");
   entry->module=ConstantString("PS");
```
