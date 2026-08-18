# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 943_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `943_1`)

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
     register const PixelPacket
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
     if ((Ar == (const PixelPacket *) NULL) ||
@@ -267,7 +263,7 @@
         status=MagickFalse;
         continue;
       }
-    for (x=0; x < (ssize_t) images->columns; x++)
+    for (x=0; x < (ssize_t) Cr_image->columns; x++)
     {
       switch (op)
       {
@@ -308,55 +304,70 @@
             gamma;
 
           gamma=PerceptibleReciprocal(Br->red*Br->red+Bi->red*Bi->red+snr);
-          Cr->red=gamma*(Ar->red*Br->red+Ai->red*Bi->red);
-          Ci->red=gamma*(Ai->red*Br->red-Ar->red*Bi->red);
-          gamma=PerceptibleReciprocal(Br->green*Br->green+Bi->green*Bi->green+
-            snr);
-          Cr->green=gamma*(Ar->green*Br->green+Ai->green*Bi->green);
-          Ci->green=gamma*(Ai->green*Br->green-Ar->green*Bi->green);
-          gamma=PerceptibleReciprocal(Br->blue*Br->blue+Bi->blue*Bi->blue+snr);
-          Cr->blue=gamma*(Ar->blue*Br->blue+Ai->blue*Bi->blue);
-          Ci->blue=gamma*(Ai->blue*Br->blue-Ar->blue*Bi->blue);
+          Cr->red=gamma*((double) Ar->red*Br->red+(double) Ai->red*Bi->red);
+          Ci->red=gamma*((double) Ai->red*Br->red-(double) Ar->red*Bi->red);
+          gamma=PerceptibleReciprocal((double) Br->green*Br->green+(double)
+            Bi->green*Bi->green+snr);
+          Cr->green=gamma*((double) Ar->green*Br->green+(double)
+            Ai->green*Bi->green);
+          Ci->green=gamma*((double) Ai->green*Br->green-(double)
+            Ar->green*Bi->green);
+          gamma=PerceptibleReciprocal((double) Br->blue*Br->blue+(double)
+            Bi->blue*Bi->blue+snr);
+          Cr->blue=gamma*((double) Ar->blue*Br->blue+(double)
+            Ai->blue*Bi->blue);
+          Ci->blue=gamma*((double) Ai->blue*Br->blue-(double)
+             Ar->blue*Bi->blue);
           if (images->matte != MagickFalse)
             {
-              gamma=PerceptibleReciprocal(Br->opacity*Br->opacity+Bi->opacity*
-                Bi->opacity+snr);
-              Cr->opacity=gamma*(Ar->opacity*Br->opacity+Ai->opacity*
-                Bi->opacity);
-              Ci->opacity=gamma*(Ai->opacity*Br->opacity-Ar->opacity*
-                Bi->opacity);
+              gamma=PerceptibleReciprocal((double) Br->opacity*Br->opacity+
+                (double) Bi->opacity*Bi->opacity+snr);
+              Cr->opacity=gamma*((double) Ar->opacity*Br->opacity+(double)
+                Ai->opacity*Bi->opacity);
+              Ci->opacity=gamma*((double) Ai->opacity*Br->opacity-(double)
+                Ar->opacity*Bi->opacity);
             }
           break;
         }
         case MagnitudePhaseComplexOperator:
         {
-          Cr->red=sqrt(Ar->red*Ar->red+Ai->red*Ai->red);
-          Ci->red=atan2(Ai->red,Ar->red)/(2.0*MagickPI)+0.5;
-          Cr->green=sqrt(Ar->green*Ar->green+Ai->green*Ai->green);
-          Ci->green=atan2(Ai->green,Ar->green)/(2.0*MagickPI)+0.5;
-          Cr->blue=sqrt(Ar->blue*Ar->blue+Ai->blue*Ai->blue);
+          Cr->red=sqrt((double) Ar->red*Ar->red+(double) Ai->red*Ai->red);
+          Ci->red=atan2((double) Ai->red,(double) Ar->red)/(2.0*MagickPI)+0.5;
+          Cr->green=sqrt((double) Ar->green*Ar->green+(double)
+            Ai->green*Ai->green);
+          Ci->green=atan2((double) Ai->green,(double) Ar->green)/
+            (2.0*MagickPI)+0.5;
+          Cr->blue=sqrt((double) Ar->blue*Ar->blue+(double) Ai->blue*Ai->blue);
           Ci->blue=atan2(Ai->blue,Ar->blue)/(2.0*MagickPI)+0.5;
           if (images->matte != MagickFalse)
             {
-              Cr->opacity=sqrt(Ar->opacity*Ar->opacity+Ai->opacity*Ai->opacity);
-              Ci->opacity=atan2(Ai->opacity,Ar->opacity)/(2.0*MagickPI)+0.5;
+              Cr->opacity=sqrt((double) Ar->opacity*Ar->opacity+(double)
+                Ai->opacity*Ai->opacity);
+              Ci->opacity=atan2((double) Ai->opacity,(double) Ar->opacity)/
+                (2.0*MagickPI)+0.5;
             }
           break;
         }
         case MultiplyComplexOperator:
         {
-          Cr->red=QuantumScale*(Ar->red*Br->red-Ai->red*Bi->red);
-          Ci->red=QuantumScale*(Ai->red*Br->red+Ar->red*Bi->red);
-          Cr->green=QuantumScale*(Ar->green*Br->green-Ai->green*Bi->green);
-          Ci->green=QuantumScale*(Ai->green*Br->green+Ar->green*Bi->green);
-          Cr->blue=QuantumScale*(Ar->blue*Br->blue-Ai->blue*Bi->blue);
-          Ci->blue=QuantumScale*(Ai->blue*Br->blue+Ar->blue*Bi->blue);
+          Cr->red=QuantumScale*((double) Ar->red*Br->red-(double)
+            Ai->red*Bi->red);
+          Ci->red=QuantumScale*((double) Ai->red*Br->red+(double)
+            Ar->red*Bi->red);
+          Cr->green=QuantumScale*((double) Ar->green*Br->green-(double)
+            Ai->green*Bi->green);
+          Ci->green=QuantumScale*((double) Ai->green*Br->green+(double)
+            Ar->green*Bi->green);
+          Cr->blue=QuantumScale*((double) Ar->blue*Br->blue-(double)
+            Ai->blue*Bi->blue);
+          Ci->blue=QuantumScale*((double) Ai->blue*Br->blue+(double)
+            Ar->blue*Bi->blue);
           if (images->matte != MagickFalse)
             {
-              Cr->opacity=QuantumScale*(Ar->opacity*Br->opacity-Ai->opacity*
-                Bi->opacity);
-              Ci->opacity=QuantumScale*(Ai->opacity*Br->opacity+Ar->opacity*
-                Bi->opacity);
+              Cr->opacity=QuantumScale*((double) Ar->opacity*Br->opacity-
+                (double) Ai->opacity*Bi->opacity);
+              Ci->opacity=QuantumScale*((double) Ai->opacity*Br->opacity+
+                (double) Ar->opacity*Bi->opacity);
             }
           break;
         }
@@ -383,7 +394,7 @@
           Ci->green=Ai->green-Bi->green;
           Cr->blue=Ar->blue-Br->blue;
           Ci->blue=Ai->blue-Bi->blue;
-          if (images->matte != MagickFalse)
+          if (Cr_image->matte != MagickFalse)
             {
               Cr->opacity=Ar->opacity-Br->opacity;
               Ci->opacity=Ai->opacity-Bi->opacity;
```
