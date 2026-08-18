# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 364_3
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `364_3`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 219-259 of the vulnerable file.

    file=(FILE *) NULL;
    if (unique_file != -1)
      file=fdopen(unique_file,"wb");
    if ((unique_file == -1) || (file == (FILE *) NULL))
      {
        (void) RelinquishUniqueFileResource(filename);
        read_info=DestroyImageInfo(read_info);
        ThrowFileException(exception,FileOpenError,"UnableToWriteFile",
          image->filename);
        image=DestroyImageList(image);
        return((Image *) NULL);
      }
    length=fwrite("SFW94A",1,6,file);
    (void) length;
    filesize=65535UL*magick[2]+256L*magick[1]+magick[0];
    for (i=0; i < (ssize_t) filesize; i++)
    {
      c=ReadBlobByte(pwp_image);
      if (c == EOF)
        break;
      (void) fputc(c,file);
    }
    (void) fclose(file);
    if (c == EOF)
      {
        (void) RelinquishUniqueFileResource(filename);
        read_info=DestroyImageInfo(read_info);
        ThrowReaderException(CorruptImageError,"UnexpectedEndOfFile");
      }
    next_image=ReadImage(read_info,exception);
    if (next_image == (Image *) NULL)
      break;
    (void) FormatLocaleString(next_image->filename,MagickPathExtent,
      "slide_%02ld.sfw",(long) next_image->scene);
    if (image == (Image *) NULL)
      image=next_image;
    else
      {
        /*
          Link image into image list.
        */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -236,7 +236,8 @@
       c=ReadBlobByte(pwp_image);
       if (c == EOF)
         break;
-      (void) fputc(c,file);
+      if (fputc(c,file) != c)
+        break;
     }
     (void) fclose(file);
     if (c == EOF)
```
