# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 923_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `923_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 190-230 of the vulnerable file.

    progress;

  MagickPixelPacket
    zero;

  MagickRealType
    number_pixels;

  ssize_t
    y;

  assert(image != (const Image *) NULL);
  assert(image->signature == MagickCoreSignature);
  if (image->debug != MagickFalse)
    (void) LogMagickEvent(TraceEvent,GetMagickModule(),"%s",image->filename);
  assert(exception != (ExceptionInfo *) NULL);
  assert(exception->signature == MagickCoreSignature);
  threshold_image=CloneImage(image,0,0,MagickTrue,exception);
  if (threshold_image == (Image *) NULL)
    return((Image *) NULL);
  if (SetImageStorageClass(threshold_image,DirectClass) == MagickFalse)
    {
      InheritException(exception,&threshold_image->exception);
      threshold_image=DestroyImage(threshold_image);
      return((Image *) NULL);
    }
  /*
    Local adaptive threshold.
  */
  status=MagickTrue;
  progress=0;
  GetMagickPixelPacket(image,&zero);
  number_pixels=(MagickRealType) (width*height);
  image_view=AcquireVirtualCacheView(image,exception);
  threshold_view=AcquireAuthenticCacheView(threshold_image,exception);
#if defined(MAGICKCORE_OPENMP_SUPPORT)
  #pragma omp parallel for schedule(static) shared(progress,status) \
    magick_number_threads(image,threshold_image,image->rows,1)
#endif
  for (y=0; y < (ssize_t) image->rows; y++)
  {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -207,6 +207,8 @@
   threshold_image=CloneImage(image,0,0,MagickTrue,exception);
   if (threshold_image == (Image *) NULL)
     return((Image *) NULL);
+  if (width == 0)
+    return(threshold_image);
   if (SetImageStorageClass(threshold_image,DirectClass) == MagickFalse)
     {
       InheritException(exception,&threshold_image->exception);
```
