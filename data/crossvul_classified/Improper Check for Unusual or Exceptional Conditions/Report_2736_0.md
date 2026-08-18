# CrossVul Fix Pair: Improper Check for Unusual or Exceptional Conditions in c
**Pair ID:** 2736_0
**Vulnerability Class:** Improper Check for Unusual or Exceptional Conditions
**CWE:** CWE-754
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2736_0`)

## Vulnerability Information & PoC

## Description
Improper Check for Unusual or Exceptional Conditions - The programmer may assume that certain events or conditions will never occur or do not need to be worried about, such as low memory conditions, lack of access to resources due to restrictive permis...

## Vulnerable Code
```c
Lines 4044-4084 of the vulnerable file.


  assert(exception != (ExceptionInfo *) NULL);
  assert(exception->signature == MagickSignature);
  logging=LogMagickEvent(CoderEvent,GetMagickModule(),"Enter ReadPNGImage()");
  image=AcquireImage(image_info);
  mng_info=(MngInfo *) NULL;
  status=OpenBlob(image_info,image,ReadBinaryBlobMode,exception);

  if (status == MagickFalse)
    ThrowReaderException(FileOpenError,"UnableToOpenFile");

  /*
    Verify PNG signature.
  */
  count=ReadBlob(image,8,(unsigned char *) magic_number);

  if (count < 8 || memcmp(magic_number,"\211PNG\r\n\032\n",8) != 0)
    ThrowReaderException(CorruptImageError,"ImproperImageHeader");

  /*
    Allocate a MngInfo structure.
  */
  mng_info=(MngInfo *) AcquireMagickMemory(sizeof(MngInfo));

  if (mng_info == (MngInfo *) NULL)
    ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");

  /*
    Initialize members of the MngInfo structure.
  */
  (void) ResetMagickMemory(mng_info,0,sizeof(MngInfo));
  mng_info->image=image;

  image=ReadOnePNGImage(mng_info,image_info,exception);
  mng_info=MngInfoFreeStruct(mng_info);

  if (image == (Image *) NULL)
    {
      if (logging != MagickFalse)
        (void) LogMagickEvent(CoderEvent,GetMagickModule(),
          "exit ReadPNGImage() with error");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4061,6 +4061,12 @@
     ThrowReaderException(CorruptImageError,"ImproperImageHeader");
 
   /*
+     Verify that file size large enough to contain a PNG datastream.
+  */
+  if (GetBlobSize(image) < 61)
+    ThrowReaderException(CorruptImageError,"InsufficientImageDataInFile");
+
+  /*
     Allocate a MngInfo structure.
   */
   mng_info=(MngInfo *) AcquireMagickMemory(sizeof(MngInfo));
@@ -4939,6 +4945,12 @@
 
   if (count < 8 || memcmp(magic_number,"\213JNG\r\n\032\n",8) != 0)
     ThrowReaderException(CorruptImageError,"ImproperImageHeader");
+
+  /*
+     Verify that file size large enough to contain a JNG datastream.
+  */
+  if (GetBlobSize(image) < 147)
+    ThrowReaderException(CorruptImageError,"InsufficientImageDataInFile");
 
   /* Allocate a MngInfo structure.  */
 
@@ -7488,7 +7500,7 @@
 #endif
 
   entry=SetMagickInfo("MNG");
-  entry->seekable_stream=MagickTrue;  /* To do: eliminate this. */
+  entry->seekable_stream=MagickTrue;
 
 #if defined(MAGICKCORE_PNG_DELEGATE)
   entry->decoder=(DecodeImageHandler *) ReadMNGImage;
@@ -7513,6 +7525,7 @@
 #endif
 
   entry->magick=(IsImageFormatHandler *) IsPNG;
+  entry->seekable_stream=MagickTrue;
   entry->adjoin=MagickFalse;
   entry->description=ConstantString("Portable Network Graphics");
   entry->mime_type=ConstantString("image/png");
@@ -7532,6 +7545,7 @@
 #endif
 
   entry->magick=(IsImageFormatHandler *) IsPNG;
+  entry->seekable_stream=MagickTrue;
   entry->adjoin=MagickFalse;
   entry->description=ConstantString(
             "8-bit indexed with optional binary transparency");
@@ -7562,6 +7576,7 @@
 #endif
 
   entry->magick=(IsImageFormatHandler *) IsPNG;
+  entry->seekable_stream=MagickTrue;
   entry->adjoin=MagickFalse;
   entry->description=ConstantString("opaque or binary transparent 24-bit RGB");
   entry->mime_type=ConstantString("image/png");
@@ -7576,6 +7591,7 @@
 #endif
 
   entry->magick=(IsImageFormatHandler *) IsPNG;
+  entry->seekable_stream=MagickTrue;
   entry->adjoin=MagickFalse;
   entry->description=ConstantString("opaque or transparent 32-bit RGBA");
   entry->mime_type=ConstantString("image/png");
@@ -7590,6 +7606,7 @@
 #endif
 
   entry->magick=(IsImageFormatHandler *) IsPNG;
+  entry->seekable_stream=MagickTrue;
   entry->adjoin=MagickFalse;
   entry->description=ConstantString("opaque or binary transparent 48-bit RGB");
   entry->mime_type=ConstantString("image/png");
@@ -7604,6 +7621,7 @@
 #endif
 
   entry->magick=(IsImageFormatHandler *) IsPNG;
+  entry->seekable_stream=MagickTrue;
   entry->adjoin=MagickFalse;
   entry->description=ConstantString("opaque or transparent 64-bit RGBA");
   entry->mime_type=ConstantString("image/png");
@@ -7618,6 +7636,7 @@
 #endif
 
   entry->magick=(IsImageFormatHandler *) IsPNG;
+  entry->seekable_stream=MagickTrue;
   entry->adjoin=MagickFalse;
   entry->description=ConstantString(
      "PNG inheriting bit-depth, color-type from original if possible");
@@ -7635,6 +7654,7 @@
 #endif
 
   entry->magick=(IsImageFormatHandler *) IsJNG;
+  entry->seekable_stream=MagickTrue;
   entry->adjoin=MagickFalse;
   entry->description=ConstantString("JPEG Network Graphics");
   entry->mime_type=ConstantString("image/x-jng");
```
