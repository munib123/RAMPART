# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 2578_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2578_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 1020-1060 of the vulnerable file.

  /*
    Open image file.
  */
  assert(image_info != (const ImageInfo *) NULL);
  assert(image_info->signature == MagickSignature);
  if (image_info->debug != MagickFalse)
    (void) LogMagickEvent(TraceEvent,GetMagickModule(),"%s",
      image_info->filename);
  assert(exception != (ExceptionInfo *) NULL);
  assert(exception->signature == MagickSignature);
  debug=IsEventLogging();
  (void) debug;
  image=AcquireImage(image_info);
  status=OpenBlob(image_info,image,ReadBinaryBlobMode,exception);
  if (status == MagickFalse)
    {
      image=DestroyImageList(image);
      return((Image *) NULL);
    }
  /*
    Initialize JPEG parameters.
  */
  (void) ResetMagickMemory(&error_manager,0,sizeof(error_manager));
  (void) ResetMagickMemory(&jpeg_info,0,sizeof(jpeg_info));
  (void) ResetMagickMemory(&jpeg_error,0,sizeof(jpeg_error));
  jpeg_info.err=jpeg_std_error(&jpeg_error);
  jpeg_info.err->emit_message=(void (*)(j_common_ptr,int)) JPEGWarningHandler;
  jpeg_info.err->error_exit=(void (*)(j_common_ptr)) JPEGErrorHandler;
  memory_info=(MemoryInfo *) NULL;
  error_manager.image=image;
  if (setjmp(error_manager.error_recovery) != 0)
    {
      jpeg_destroy_decompress(&jpeg_info);
      if (error_manager.profile != (StringInfo *) NULL)
        error_manager.profile=DestroyStringInfo(error_manager.profile);
      (void) CloseBlob(image);
      number_pixels=(MagickSizeType) image->columns*image->rows;
      if (number_pixels != 0)
        return(GetFirstImageInList(image));
      InheritException(exception,&image->exception);
      return(DestroyImage(image));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1037,6 +1037,11 @@
       return((Image *) NULL);
     }
   /*
+    Verify that file size large enough to contain a JPEG datastream.
+  */
+  if (GetBlobSize(image) < 107)
+    ThrowReaderException(CorruptImageError,"InsufficientImageDataInFile");
+  /*
     Initialize JPEG parameters.
   */
   (void) ResetMagickMemory(&error_manager,0,sizeof(error_manager));
@@ -1511,6 +1516,7 @@
 #endif
   entry->magick=(IsImageFormatHandler *) IsJPEG;
   entry->adjoin=MagickFalse;
+  entry->seekable_stream=MagickTrue;
   entry->description=ConstantString(description);
   if (*version != '\0')
     entry->version=ConstantString(version);
@@ -1527,6 +1533,7 @@
 #endif
   entry->magick=(IsImageFormatHandler *) IsJPEG;
   entry->adjoin=MagickFalse;
+  entry->seekable_stream=MagickTrue;
   entry->description=ConstantString(description);
   if (*version != '\0')
     entry->version=ConstantString(version);
@@ -1542,6 +1549,7 @@
   entry->encoder=(EncodeImageHandler *) WriteJPEGImage;
 #endif
   entry->adjoin=MagickFalse;
+  entry->seekable_stream=MagickTrue;
   entry->description=ConstantString(description);
   if (*version != '\0')
     entry->version=ConstantString(version);
@@ -1557,6 +1565,7 @@
   entry->encoder=(EncodeImageHandler *) WriteJPEGImage;
 #endif
   entry->adjoin=MagickFalse;
+  entry->seekable_stream=MagickTrue;
   entry->description=ConstantString(description);
   if (*version != '\0')
     entry->version=ConstantString(version);
@@ -1572,6 +1581,7 @@
   entry->encoder=(EncodeImageHandler *) WriteJPEGImage;
 #endif
   entry->adjoin=MagickFalse;
+  entry->seekable_stream=MagickTrue;
   entry->description=ConstantString(description);
   if (*version != '\0')
     entry->version=ConstantString(version);
```
