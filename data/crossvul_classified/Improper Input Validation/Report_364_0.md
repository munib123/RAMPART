# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 364_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `364_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 244-284 of the vulnerable file.

          }
        if (LocaleNCompare(header,"rtype:",6) == 0)
          {
            (void) sscanf(header+6,"%lu",&type);
            break;
          }
        break;
      }
    }
  }
  /*
    Read CALS pixels.
  */
  file=(FILE *) NULL;
  unique_file=AcquireUniqueFileResource(filename);
  if (unique_file != -1)
    file=fdopen(unique_file,"wb");
  if ((unique_file == -1) || (file == (FILE *) NULL))
    ThrowImageException(FileOpenError,"UnableToCreateTemporaryFile");
  while ((c=ReadBlobByte(image)) != EOF)
    (void) fputc(c,file);
  (void) fclose(file);
  (void) CloseBlob(image);
  image=DestroyImage(image);
  read_info=CloneImageInfo(image_info);
  SetImageInfoBlob(read_info,(void *) NULL,0);
  (void) FormatLocaleString(read_info->filename,MagickPathExtent,"group4:%s",
    filename);
  (void) FormatLocaleString(message,MagickPathExtent,"%lux%lu",width,height);
  (void) CloneString(&read_info->size,message);
  (void) FormatLocaleString(message,MagickPathExtent,"%lu",density);
  (void) CloneString(&read_info->density,message);
  read_info->orientation=(OrientationType) orientation;
  image=ReadImage(read_info,exception);
  if (image != (Image *) NULL)
    {
      (void) CopyMagickString(image->filename,image_info->filename,
        MagickPathExtent);
      (void) CopyMagickString(image->magick_filename,image_info->filename,
        MagickPathExtent);
      (void) CopyMagickString(image->magick,"CALS",MagickPathExtent);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -261,7 +261,8 @@
   if ((unique_file == -1) || (file == (FILE *) NULL))
     ThrowImageException(FileOpenError,"UnableToCreateTemporaryFile");
   while ((c=ReadBlobByte(image)) != EOF)
-    (void) fputc(c,file);
+    if (fputc(c,file) != c)
+      break;
   (void) fclose(file);
   (void) CloseBlob(image);
   image=DestroyImage(image);
```
