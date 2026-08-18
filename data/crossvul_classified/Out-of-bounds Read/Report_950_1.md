# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 950_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `950_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 231-274 of the vulnerable file.

  #pragma omp parallel for schedule(static) shared(progress,status) \
    magick_number_threads(images,complex_images,images->rows,1L)
#endif
  for (y=0; y < (ssize_t) images->rows; y++)
  {
    register const PixelPacket
      *magick_restrict Ai,
      *magick_restrict Ar,
      *magick_restrict Bi,
      *magick_restrict Br;

    register PixelPacket
      *magick_restrict Ci,
      *magick_restrict Cr;

    register ssize_t
      x;

    if (status == MagickFalse)
      continue;
    Ar=GetCacheViewVirtualPixels(Ar_view,0,y,Ar_image->columns,1,exception);
    Ai=GetCacheViewVirtualPixels(Ai_view,0,y,Ai_image->columns,1,exception);
    Br=GetCacheViewVirtualPixels(Br_view,0,y,Br_image->columns,1,exception);
    Bi=GetCacheViewVirtualPixels(Bi_view,0,y,Bi_image->columns,1,exception);
    Cr=QueueCacheViewAuthenticPixels(Cr_view,0,y,Cr_image->columns,1,exception);
    Ci=QueueCacheViewAuthenticPixels(Ci_view,0,y,Ci_image->columns,1,exception);
    if ((Ar == (const PixelPacket *) NULL) ||
        (Ai == (const PixelPacket *) NULL) ||
        (Br == (const PixelPacket *) NULL) ||
        (Bi == (const PixelPacket *) NULL) ||
        (Cr == (PixelPacket *) NULL) || (Ci == (PixelPacket *) NULL))
      {
        status=MagickFalse;
        continue;
      }
    for (x=0; x < (ssize_t) images->columns; x++)
    {
      switch (op)
      {
        case AddComplexOperator:
        {
          Cr->red=Ar->red+Br->red;
          Ci->red=Ai->red+Bi->red;
          Cr->green=Ar->green+Br->green;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -248,10 +248,14 @@
 
     if (status == MagickFalse)
       continue;
-    Ar=GetCacheViewVirtualPixels(Ar_view,0,y,Ar_image->columns,1,exception);
-    Ai=GetCacheViewVirtualPixels(Ai_view,0,y,Ai_image->columns,1,exception);
-    Br=GetCacheViewVirtualPixels(Br_view,0,y,Br_image->columns,1,exception);
-    Bi=GetCacheViewVirtualPixels(Bi_view,0,y,Bi_image->columns,1,exception);
+    Ar=GetCacheViewVirtualPixels(Ar_view,0,y,
+      MagickMax(Ar_image->columns,Cr_image->columns),1,exception);
+    Ai=GetCacheViewVirtualPixels(Ai_view,0,y,
+      MagickMax(Ai_image->columns,Ci_image->columns),1,exception);
+    Br=GetCacheViewVirtualPixels(Br_view,0,y,
+      MagickMax(Br_image->columns,Cr_image->columns),1,exception);
+    Bi=GetCacheViewVirtualPixels(Bi_view,0,y,
+      MagickMax(Bi_image->columns,Ci_image->columns),1,exception);
     Cr=QueueCacheViewAuthenticPixels(Cr_view,0,y,Cr_image->columns,1,exception);
     Ci=QueueCacheViewAuthenticPixels(Ci_view,0,y,Ci_image->columns,1,exception);
     if ((Ar == (const PixelPacket *) NULL) ||
```
