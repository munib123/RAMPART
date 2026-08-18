# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 4779_4
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4779_4`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 2484-2524 of the vulnerable file.

    {
      (void) CloseBlob(image);
      return(MagickFalse);
    }
  huffman_image->endian=MSBEndian;
  file=(FILE *) NULL;
  unique_file=AcquireUniqueFileResource(filename);
  if (unique_file != -1)
    file=fdopen(unique_file,"wb");
  if ((unique_file == -1) || (file == (FILE *) NULL))
    {
      ThrowFileException(&image->exception,FileOpenError,
        "UnableToCreateTemporaryFile",filename);
      return(MagickFalse);
    }
  (void) FormatLocaleString(huffman_image->filename,MaxTextExtent,"tiff:%s",
    filename);
  (void) SetImageType(huffman_image,BilevelType);
  write_info=CloneImageInfo((ImageInfo *) NULL);
  SetImageInfoFile(write_info,file);
  (void) SetImageType(image,BilevelType);
  (void) SetImageDepth(image,1);
  write_info->compression=Group4Compression;
  write_info->type=BilevelType;
  (void) SetImageOption(write_info,"quantum:polarity","min-is-white");
  status=WriteTIFFImage(write_info,huffman_image);
  (void) fflush(file);
  write_info=DestroyImageInfo(write_info);
  if (status == MagickFalse)
    {
      InheritException(&image->exception,&huffman_image->exception);
      huffman_image=DestroyImage(huffman_image);
      (void) fclose(file);
      (void) RelinquishUniqueFileResource(filename);
      return(MagickFalse);
    }
  tiff=TIFFOpen(filename,"rb");
  if (tiff == (TIFF *) NULL)
    {
      huffman_image=DestroyImage(huffman_image);
      (void) fclose(file);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2501,8 +2501,8 @@
   (void) SetImageType(huffman_image,BilevelType);
   write_info=CloneImageInfo((ImageInfo *) NULL);
   SetImageInfoFile(write_info,file);
+  (void) SetImageDepth(image,1);
   (void) SetImageType(image,BilevelType);
-  (void) SetImageDepth(image,1);
   write_info->compression=Group4Compression;
   write_info->type=BilevelType;
   (void) SetImageOption(write_info,"quantum:polarity","min-is-white");
```
