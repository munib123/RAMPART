# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 932_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `932_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 150-190 of the vulnerable file.

    *Ai_image,
    *Ar_image,
    *Bi_image,
    *Br_image;

  double
    snr;

  Image
    *Ci_image,
    *complex_images,
    *Cr_image,
    *image;

  MagickBooleanType
    status;

  MagickOffsetType
    progress;

  ssize_t
    y;

  assert(images != (Image *) NULL);
  assert(images->signature == MagickCoreSignature);
  if (images->debug != MagickFalse)
    (void) LogMagickEvent(TraceEvent,GetMagickModule(),"%s",images->filename);
  assert(exception != (ExceptionInfo *) NULL);
  assert(exception->signature == MagickCoreSignature);
  if (images->next == (Image *) NULL)
    {
      (void) ThrowMagickException(exception,GetMagickModule(),ImageError,
        "ImageSequenceRequired","`%s'",images->filename);
      return((Image *) NULL);
    }
  image=CloneImage(images,0,0,MagickTrue,exception);
  if (image == (Image *) NULL)
    return((Image *) NULL);
  if (SetImageStorageClass(image,DirectClass,exception) == MagickFalse)
    {
      image=DestroyImageList(image);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -167,6 +167,9 @@
   MagickOffsetType
     progress;
 
+  size_t
+    number_channels;
+
   ssize_t
     y;
 
@@ -219,6 +222,10 @@
     }
   Cr_image=complex_images;
   Ci_image=complex_images->next;
+  number_channels=MagickMin(MagickMin(MagickMin(
+    Ar_image->number_channels,Ai_image->number_channels),MagickMin(
+    Br_image->number_channels,Bi_image->number_channels)),MagickMin(
+    Cr_image->number_channels,Ci_image->number_channels));
   Ar_view=AcquireVirtualCacheView(Ar_image,exception);
   Ai_view=AcquireVirtualCacheView(Ai_image,exception);
   Br_view=AcquireVirtualCacheView(Br_image,exception);
@@ -266,7 +273,7 @@
       register ssize_t
         i;
 
-      for (i=0; i < (ssize_t) GetPixelChannels(Cr_image); i++)
+      for (i=0; i < (ssize_t) number_channels; i++)
       {
         switch (op)
         {
```
