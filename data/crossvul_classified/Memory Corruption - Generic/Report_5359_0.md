# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5359_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5359_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1414-1473 of the vulnerable file.

               (void) FormatLocaleString(sampling_factor,MagickPathExtent,
                 "%dx%d",horizontal,vertical);
               (void) SetImageProperty(image,"jpeg:sampling-factor",
                 sampling_factor,exception);
               (void) LogMagickEvent(CoderEvent,GetMagickModule(),
                 "Sampling Factors: %s",sampling_factor);
             }
         }
#endif
        break;
      }
      case COMPRESSION_OJPEG: image->compression=JPEGCompression; break;
#if defined(COMPRESSION_LZMA)
      case COMPRESSION_LZMA: image->compression=LZMACompression; break;
#endif
      case COMPRESSION_LZW: image->compression=LZWCompression; break;
      case COMPRESSION_DEFLATE: image->compression=ZipCompression; break;
      case COMPRESSION_ADOBE_DEFLATE: image->compression=ZipCompression; break;
      default: image->compression=RLECompression; break;
    }
    /*
      Allocate memory for the image and pixel buffer.
    */
    quantum_info=AcquireQuantumInfo(image_info,image);
    if (quantum_info == (QuantumInfo *) NULL)
      {
        TIFFClose(tiff);
        ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
      }
    if (sample_format == SAMPLEFORMAT_UINT)
      status=SetQuantumFormat(image,quantum_info,UnsignedQuantumFormat);
    if (sample_format == SAMPLEFORMAT_INT)
      status=SetQuantumFormat(image,quantum_info,SignedQuantumFormat);
    if (sample_format == SAMPLEFORMAT_IEEEFP)
      status=SetQuantumFormat(image,quantum_info,FloatingPointQuantumFormat);
    if (status == MagickFalse)
      {
        TIFFClose(tiff);
        quantum_info=DestroyQuantumInfo(quantum_info);
        ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
      }
    status=MagickTrue;
    switch (photometric)
    {
      case PHOTOMETRIC_MINISBLACK:
      {
        quantum_info->min_is_white=MagickFalse;
        break;
      }
      case PHOTOMETRIC_MINISWHITE:
      {
        quantum_info->min_is_white=MagickTrue;
        break;
      }
      default:
        break;
    }
    tiff_status=TIFFGetFieldDefaulted(tiff,TIFFTAG_EXTRASAMPLES,&extra_samples,
      &sample_info);
    if (tiff_status == 1)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1431,69 +1431,7 @@
       case COMPRESSION_ADOBE_DEFLATE: image->compression=ZipCompression; break;
       default: image->compression=RLECompression; break;
     }
-    /*
-      Allocate memory for the image and pixel buffer.
-    */
-    quantum_info=AcquireQuantumInfo(image_info,image);
-    if (quantum_info == (QuantumInfo *) NULL)
-      {
-        TIFFClose(tiff);
-        ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
-      }
-    if (sample_format == SAMPLEFORMAT_UINT)
-      status=SetQuantumFormat(image,quantum_info,UnsignedQuantumFormat);
-    if (sample_format == SAMPLEFORMAT_INT)
-      status=SetQuantumFormat(image,quantum_info,SignedQuantumFormat);
-    if (sample_format == SAMPLEFORMAT_IEEEFP)
-      status=SetQuantumFormat(image,quantum_info,FloatingPointQuantumFormat);
-    if (status == MagickFalse)
-      {
-        TIFFClose(tiff);
-        quantum_info=DestroyQuantumInfo(quantum_info);
-        ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
-      }
-    status=MagickTrue;
-    switch (photometric)
-    {
-      case PHOTOMETRIC_MINISBLACK:
-      {
-        quantum_info->min_is_white=MagickFalse;
-        break;
-      }
-      case PHOTOMETRIC_MINISWHITE:
-      {
-        quantum_info->min_is_white=MagickTrue;
-        break;
-      }
-      default:
-        break;
-    }
-    tiff_status=TIFFGetFieldDefaulted(tiff,TIFFTAG_EXTRASAMPLES,&extra_samples,
-      &sample_info);
-    if (tiff_status == 1)
-      {
-        (void) SetImageProperty(image,"tiff:alpha","unspecified",exception);
-        if (extra_samples == 0)
-          {
-            if ((samples_per_pixel == 4) && (photometric == PHOTOMETRIC_RGB))
-              image->alpha_trait=BlendPixelTrait;
-          }
-        else
-          for (i=0; i < extra_samples; i++)
-          {
-            image->alpha_trait=BlendPixelTrait;
-            if (sample_info[i] == EXTRASAMPLE_ASSOCALPHA)
-              {
-                SetQuantumAlphaType(quantum_info,DisassociatedQuantumAlpha);
-                (void) SetImageProperty(image,"tiff:alpha","associated",
-                  exception);
-              }
-            else
-              if (sample_info[i] == EXTRASAMPLE_UNASSALPHA)
-                (void) SetImageProperty(image,"tiff:alpha","unassociated",
-                  exception);
-          }
-      }
+    quantum_info=(QuantumInfo *) NULL;
     if ((photometric == PHOTOMETRIC_PALETTE) &&
         (pow(2.0,1.0*bits_per_sample) <= MaxColormapSize))
       {
@@ -1560,15 +1498,75 @@
       {
         if (image_info->number_scenes != 0)
           if (image->scene >= (image_info->scene+image_info->number_scenes-1))
-            {
-              quantum_info=DestroyQuantumInfo(quantum_info);
-              break;
-            }
+            break;
         goto next_tiff_frame;
       }
     status=SetImageExtent(image,image->columns,image->rows,exception);
     if (status == MagickFalse)
       return(DestroyImageList(image));
+    /*
+      Allocate memory for the image and pixel buffer.
+    */
+    quantum_info=AcquireQuantumInfo(image_info,image);
+    if (quantum_info == (QuantumInfo *) NULL)
+      {
+        TIFFClose(tiff);
+        ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
+      }
+    if (sample_format == SAMPLEFORMAT_UINT)
+      status=SetQuantumFormat(image,quantum_info,UnsignedQuantumFormat);
+    if (sample_format == SAMPLEFORMAT_INT)
+      status=SetQuantumFormat(image,quantum_info,SignedQuantumFormat);
+    if (sample_format == SAMPLEFORMAT_IEEEFP)
+      status=SetQuantumFormat(image,quantum_info,FloatingPointQuantumFormat);
+    if (status == MagickFalse)
+      {
+        TIFFClose(tiff);
+        quantum_info=DestroyQuantumInfo(quantum_info);
+        ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
+      }
+    status=MagickTrue;
+    switch (photometric)
+    {
+      case PHOTOMETRIC_MINISBLACK:
+      {
+        quantum_info->min_is_white=MagickFalse;
+        break;
+      }
+      case PHOTOMETRIC_MINISWHITE:
+      {
+        quantum_info->min_is_white=MagickTrue;
+        break;
+      }
+      default:
+        break;
+    }
+    tiff_status=TIFFGetFieldDefaulted(tiff,TIFFTAG_EXTRASAMPLES,&extra_samples,
+      &sample_info);
+    if (tiff_status == 1)
+      {
+        (void) SetImageProperty(image,"tiff:alpha","unspecified",exception);
+        if (extra_samples == 0)
+          {
+            if ((samples_per_pixel == 4) && (photometric == PHOTOMETRIC_RGB))
+              image->alpha_trait=BlendPixelTrait;
+          }
+        else
+          for (i=0; i < extra_samples; i++)
+          {
+            image->alpha_trait=BlendPixelTrait;
+            if (sample_info[i] == EXTRASAMPLE_ASSOCALPHA)
+              {
+                SetQuantumAlphaType(quantum_info,DisassociatedQuantumAlpha);
+                (void) SetImageProperty(image,"tiff:alpha","associated",
+                  exception);
+              }
+            else
+              if (sample_info[i] == EXTRASAMPLE_UNASSALPHA)
+                (void) SetImageProperty(image,"tiff:alpha","unassociated",
+                  exception);
+          }
+      }
     method=ReadGenericMethod;
     if (TIFFGetField(tiff,TIFFTAG_ROWSPERSTRIP,&rows_per_strip) == 1)
       {
@@ -2078,7 +2076,8 @@
     }
     SetQuantumImageType(image,quantum_type);
   next_tiff_frame:
-    quantum_info=DestroyQuantumInfo(quantum_info);
+    if (quantum_info != (QuantumInfo *) NULL)
+      quantum_info=DestroyQuantumInfo(quantum_info);
     if (photometric == PHOTOMETRIC_CIELAB)
       DecodeLabImage(image,exception);
     if ((photometric == PHOTOMETRIC_LOGL) ||
```
