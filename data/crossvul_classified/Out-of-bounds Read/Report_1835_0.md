# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 1835_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1835_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1718-1758 of the vulnerable file.

{
#define SpliceImageTag  "Splice/Image"

  CacheView
    *image_view,
    *splice_view;

  Image
    *splice_image;

  MagickBooleanType
    status;

  MagickOffsetType
    progress;

  RectangleInfo
    splice_geometry;

  ssize_t
    y;

  /*
    Allocate splice image.
  */
  assert(image != (const Image *) NULL);
  assert(image->signature == MagickCoreSignature);
  if (image->debug != MagickFalse)
    (void) LogMagickEvent(TraceEvent,GetMagickModule(),"%s",image->filename);
  assert(geometry != (const RectangleInfo *) NULL);
  assert(exception != (ExceptionInfo *) NULL);
  assert(exception->signature == MagickCoreSignature);
  splice_geometry=(*geometry);
  splice_image=CloneImage(image,image->columns+splice_geometry.width,
    image->rows+splice_geometry.height,MagickTrue,exception);
  if (splice_image == (Image *) NULL)
    return((Image *) NULL);
  if (SetImageStorageClass(splice_image,DirectClass,exception) == MagickFalse)
    {
      splice_image=DestroyImage(splice_image);
      return((Image *) NULL);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1735,6 +1735,7 @@
     splice_geometry;
 
   ssize_t
+    columns,
     y;
 
   /*
@@ -1823,6 +1824,7 @@
   */
   status=MagickTrue;
   progress=0;
+  columns=MagickMin(splice_geometry.x,(ssize_t) splice_image->columns);
   image_view=AcquireVirtualCacheView(image,exception);
   splice_view=AcquireAuthenticCacheView(splice_image,exception);
 #if defined(MAGICKCORE_OPENMP_SUPPORT)
@@ -1842,7 +1844,8 @@
 
     if (status == MagickFalse)
       continue;
-    p=GetCacheViewVirtualPixels(image_view,0,y,image->columns,1,exception);
+    p=GetCacheViewVirtualPixels(image_view,0,y,splice_image->columns,1,
+      exception);
     q=QueueCacheViewAuthenticPixels(splice_view,0,y,splice_image->columns,1,
       exception);
     if ((p == (const Quantum *) NULL) || (q == (Quantum *) NULL))
@@ -1850,7 +1853,7 @@
         status=MagickFalse;
         continue;
       }
-    for (x=0; x < splice_geometry.x; x++)
+    for (x=0; x < columns; x++)
     {
       register ssize_t
         i;
@@ -1944,10 +1947,10 @@
 
     if (status == MagickFalse)
       continue;
+    if ((y < 0) || (y >= (ssize_t)splice_image->rows))
+      continue;
     p=GetCacheViewVirtualPixels(image_view,0,y-(ssize_t) splice_geometry.height,
-      image->columns,1,exception);
-    if ((y < 0) || (y >= (ssize_t) splice_image->rows))
-      continue;
+      splice_image->columns,1,exception);
     q=QueueCacheViewAuthenticPixels(splice_view,0,y,splice_image->columns,1,
       exception);
     if ((p == (const Quantum *) NULL) || (q == (Quantum *) NULL))
@@ -1955,7 +1958,7 @@
         status=MagickFalse;
         continue;
       }
-    for (x=0; x < splice_geometry.x; x++)
+    for (x=0; x < columns; x++)
     {
       register ssize_t
         i;
```
