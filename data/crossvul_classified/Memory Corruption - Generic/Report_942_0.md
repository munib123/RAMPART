# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 942_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `942_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 212-252 of the vulnerable file.

  Br_image=images;
  Bi_image=images->next;
  if ((images->next->next != (Image *) NULL) &&
      (images->next->next->next != (Image *) NULL))
    {
      Br_image=images->next->next;
      Bi_image=images->next->next->next;
    }
  Cr_image=complex_images;
  Ci_image=complex_images->next;
  Ar_view=AcquireVirtualCacheView(Ar_image,exception);
  Ai_view=AcquireVirtualCacheView(Ai_image,exception);
  Br_view=AcquireVirtualCacheView(Br_image,exception);
  Bi_view=AcquireVirtualCacheView(Bi_image,exception);
  Cr_view=AcquireAuthenticCacheView(Cr_image,exception);
  Ci_view=AcquireAuthenticCacheView(Ci_image,exception);
  status=MagickTrue;
  progress=0;
#if defined(MAGICKCORE_OPENMP_SUPPORT)
  #pragma omp parallel for schedule(static) shared(progress,status) \
    magick_number_threads(images,complex_images,images->rows,1L)
#endif
  for (y=0; y < (ssize_t) images->rows; y++)
  {
    register const Quantum
      *magick_restrict Ai,
      *magick_restrict Ar,
      *magick_restrict Bi,
      *magick_restrict Br;

    register Quantum
      *magick_restrict Ci,
      *magick_restrict Cr;

    register ssize_t
      x;

    if (status == MagickFalse)
      continue;
    Ar=GetCacheViewVirtualPixels(Ar_view,0,y,
      MagickMax(Ar_image->columns,Cr_image->columns),1,exception);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -229,9 +229,9 @@
   progress=0;
 #if defined(MAGICKCORE_OPENMP_SUPPORT)
   #pragma omp parallel for schedule(static) shared(progress,status) \
-    magick_number_threads(images,complex_images,images->rows,1L)
-#endif
-  for (y=0; y < (ssize_t) images->rows; y++)
+    magick_number_threads(Cr_image,complex_images,Cr_image->rows,1L)
+#endif
+  for (y=0; y < (ssize_t) Cr_image->rows; y++)
   {
     register const Quantum
       *magick_restrict Ai,
@@ -248,14 +248,10 @@
 
     if (status == MagickFalse)
       continue;
-    Ar=GetCacheViewVirtualPixels(Ar_view,0,y,
-      MagickMax(Ar_image->columns,Cr_image->columns),1,exception);
-    Ai=GetCacheViewVirtualPixels(Ai_view,0,y,
-      MagickMax(Ai_image->columns,Ci_image->columns),1,exception);
-    Br=GetCacheViewVirtualPixels(Br_view,0,y,
-      MagickMax(Br_image->columns,Cr_image->columns),1,exception);
-    Bi=GetCacheViewVirtualPixels(Bi_view,0,y,
-      MagickMax(Bi_image->columns,Ci_image->columns),1,exception);
+    Ar=GetCacheViewVirtualPixels(Ar_view,0,y,Cr_image->columns,1,exception);
+    Ai=GetCacheViewVirtualPixels(Ai_view,0,y,Cr_image->columns,1,exception);
+    Br=GetCacheViewVirtualPixels(Br_view,0,y,Cr_image->columns,1,exception);
+    Bi=GetCacheViewVirtualPixels(Bi_view,0,y,Cr_image->columns,1,exception);
     Cr=QueueCacheViewAuthenticPixels(Cr_view,0,y,Cr_image->columns,1,exception);
     Ci=QueueCacheViewAuthenticPixels(Ci_view,0,y,Ci_image->columns,1,exception);
     if ((Ar == (const Quantum *) NULL) || (Ai == (const Quantum *) NULL) || 
@@ -265,12 +261,12 @@
         status=MagickFalse;
         continue;
       }
-    for (x=0; x < (ssize_t) images->columns; x++)
+    for (x=0; x < (ssize_t) Cr_image->columns; x++)
     {
       register ssize_t
         i;
 
-      for (i=0; i < (ssize_t) GetPixelChannels(images); i++)
+      for (i=0; i < (ssize_t) GetPixelChannels(Cr_image); i++)
       {
         switch (op)
         {
@@ -292,21 +288,21 @@
             double
               gamma;
 
-            gamma=PerceptibleReciprocal(Br[i]*Br[i]+Bi[i]*Bi[i]+snr);
-            Cr[i]=gamma*(Ar[i]*Br[i]+Ai[i]*Bi[i]);
-            Ci[i]=gamma*(Ai[i]*Br[i]-Ar[i]*Bi[i]);
+            gamma=PerceptibleReciprocal((double) Br[i]*Br[i]+Bi[i]*Bi[i]+snr);
+            Cr[i]=gamma*((double) Ar[i]*Br[i]+(double) Ai[i]*Bi[i]);
+            Ci[i]=gamma*((double) Ai[i]*Br[i]-(double) Ar[i]*Bi[i]);
             break;
           }
           case MagnitudePhaseComplexOperator:
           {
-            Cr[i]=sqrt(Ar[i]*Ar[i]+Ai[i]*Ai[i]);
-            Ci[i]=atan2(Ai[i],Ar[i])/(2.0*MagickPI)+0.5;
+            Cr[i]=sqrt((double) Ar[i]*Ar[i]+(double) Ai[i]*Ai[i]);
+            Ci[i]=atan2((double) Ai[i],(double) Ar[i])/(2.0*MagickPI)+0.5;
             break;
           }
           case MultiplyComplexOperator:
           {
-            Cr[i]=QuantumScale*(Ar[i]*Br[i]-Ai[i]*Bi[i]);
-            Ci[i]=QuantumScale*(Ai[i]*Br[i]+Ar[i]*Bi[i]);
+            Cr[i]=QuantumScale*((double) Ar[i]*Br[i]-(double) Ai[i]*Bi[i]);
+            Ci[i]=QuantumScale*((double) Ai[i]*Br[i]+(double) Ar[i]*Bi[i]);
             break;
           }
           case RealImaginaryComplexOperator:
```
