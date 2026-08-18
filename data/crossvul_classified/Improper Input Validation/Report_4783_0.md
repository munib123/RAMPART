# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 4783_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4783_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 378-418 of the vulnerable file.

  length=fwrite("\003\001\003\000\001\000\000\000\004\000\000\000",1,12,file);
  length=fwrite("\006\001\003\000\001\000\000\000\000\000\000\000",1,12,file);
  length=fwrite("\021\001\003\000\001\000\000\000",1,8,file);
  strip_offset=10+(12*14)+4+8;
  length=WriteLSBLong(file,(size_t) strip_offset);
  length=fwrite("\022\001\003\000\001\000\000\000",1,8,file);
  length=WriteLSBLong(file,(size_t) image_info->orientation);
  length=fwrite("\025\001\003\000\001\000\000\000\001\000\000\000",1,12,file);
  length=fwrite("\026\001\004\000\001\000\000\000",1,8,file);
  length=WriteLSBLong(file,image->rows);
  length=fwrite("\027\001\004\000\001\000\000\000\000\000\000\000",1,12,file);
  offset=(ssize_t) ftell(file)-4;
  length=fwrite("\032\001\005\000\001\000\000\000",1,8,file);
  length=WriteLSBLong(file,(size_t) (strip_offset-8));
  length=fwrite("\033\001\005\000\001\000\000\000",1,8,file);
  length=WriteLSBLong(file,(size_t) (strip_offset-8));
  length=fwrite("\050\001\003\000\001\000\000\000\002\000\000\000",1,12,file);
  length=fwrite("\000\000\000\000",1,4,file);
  length=WriteLSBLong(file,(long) image->resolution.x);
  length=WriteLSBLong(file,1);
  for (length=0; (c=ReadBlobByte(image)) != EOF; length++)
    (void) fputc(c,file);
  offset=(ssize_t) fseek(file,(ssize_t) offset,SEEK_SET);
  length=WriteLSBLong(file,(unsigned int) length);
  (void) fclose(file);
  (void) CloseBlob(image);
  image=DestroyImage(image);
  /*
    Read TIFF image.
  */
  read_info=CloneImageInfo((ImageInfo *) NULL);
  (void) FormatLocaleString(read_info->filename,MagickPathExtent,"%s",filename);
  image=ReadTIFFImage(read_info,exception);
  read_info=DestroyImageInfo(read_info);
  if (image != (Image *) NULL)
    {
      (void) CopyMagickString(image->filename,image_info->filename,
        MagickPathExtent);
      (void) CopyMagickString(image->magick_filename,image_info->filename,
        MagickPathExtent);
      (void) CopyMagickString(image->magick,"GROUP4",MagickPathExtent);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -395,8 +395,10 @@
   length=fwrite("\000\000\000\000",1,4,file);
   length=WriteLSBLong(file,(long) image->resolution.x);
   length=WriteLSBLong(file,1);
+  status=MagickTrue;
   for (length=0; (c=ReadBlobByte(image)) != EOF; length++)
-    (void) fputc(c,file);
+    if (fputc(c,file) != c)
+      status=MagickFalse;
   offset=(ssize_t) fseek(file,(ssize_t) offset,SEEK_SET);
   length=WriteLSBLong(file,(unsigned int) length);
   (void) fclose(file);
@@ -418,6 +420,8 @@
       (void) CopyMagickString(image->magick,"GROUP4",MagickPathExtent);
     }
   (void) RelinquishUniqueFileResource(filename);
+  if (status == MagickFalse)
+    image=DestroyImage(image);
   return(image);
 }
 #endif
```
