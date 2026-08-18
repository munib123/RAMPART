# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 5306_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5306_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 781-821 of the vulnerable file.

    goto FINISH;

  /* Copy postscript to temporary file */
  (void) SeekBlob(image,PS_Offset,SEEK_SET);
  (void) ReadBlob(image, 2*MaxTextExtent, magick);

  (void) SeekBlob(image,PS_Offset,SEEK_SET);
  while(PS_Size-- > 0)
    {
      (void) fputc(ReadBlobByte(image),ps_file);
    }
  (void) fclose(ps_file);

    /* Detect file format - Check magic.mgk configuration file. */
  magic_info=GetMagicInfo(magick,2*MaxTextExtent,exception);
  if(magic_info == (const MagicInfo *) NULL) goto FINISH_UNL;
  /*     printf("Detected:%s  \n",magic_info->name); */
  if(exception->severity != UndefinedException) goto FINISH_UNL;
  if(magic_info->name == (char *) NULL) goto FINISH_UNL;

  (void) CopyMagickMemory(clone_info->magick,magic_info->name,MaxTextExtent);

    /* Read nested image */
  /*FormatString(clone_info->filename,"%s:%s",magic_info->name,postscript_file);*/
  FormatLocaleString(clone_info->filename,MaxTextExtent,"%s",postscript_file);
  image2=ReadImage(clone_info,exception);

  if (!image2)
    goto FINISH_UNL;

  /*
    Replace current image with new image while copying base image
    attributes.
  */
  (void) CopyMagickMemory(image2->filename,image->filename,MaxTextExtent);
  (void) CopyMagickMemory(image2->magick_filename,image->magick_filename,MaxTextExtent);
  (void) CopyMagickMemory(image2->magick,image->magick,MaxTextExtent);
  image2->depth=image->depth;
  DestroyBlob(image2);
  image2->blob=ReferenceBlob(image->blob);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -798,7 +798,7 @@
   if(exception->severity != UndefinedException) goto FINISH_UNL;
   if(magic_info->name == (char *) NULL) goto FINISH_UNL;
 
-  (void) CopyMagickMemory(clone_info->magick,magic_info->name,MaxTextExtent);
+  (void) strncpy(clone_info->magick,magic_info->name,MaxTextExtent);
 
     /* Read nested image */
   /*FormatString(clone_info->filename,"%s:%s",magic_info->name,postscript_file);*/
```
