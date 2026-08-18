# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 1416_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1416_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 1893-1933 of the vulnerable file.

         (SetImageGray(image,exception) != MagickFalse)))
      {
        switch (compression)
        {
          case FaxCompression:
          case Group4Compression:
          {
            if (LocaleCompare(CCITTParam,"0") == 0)
              {
                (void) HuffmanEncodeImage(image_info,image,image,exception);
                break;
              }
            (void) Huffman2DEncodeImage(image_info,image,image,exception);
            break;
          }
          case JPEGCompression:
          {
            status=InjectImageBlob(image_info,image,image,"jpeg",exception);
            if (status == MagickFalse)
              {
                (void) CloseBlob(image);
                return(MagickFalse);
              }
            break;
          }
          case JPEG2000Compression:
          {
            status=InjectImageBlob(image_info,image,image,"jp2",exception);
            if (status == MagickFalse)
              {
                (void) CloseBlob(image);
                return(MagickFalse);
              }
            break;
          }
          case RLECompression:
          default:
          {
            MemoryInfo
              *pixel_info;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1910,6 +1910,7 @@
             status=InjectImageBlob(image_info,image,image,"jpeg",exception);
             if (status == MagickFalse)
               {
+                xref=(MagickOffsetType *) RelinquishMagickMemory(xref);
                 (void) CloseBlob(image);
                 return(MagickFalse);
               }
@@ -1920,6 +1921,7 @@
             status=InjectImageBlob(image_info,image,image,"jp2",exception);
             if (status == MagickFalse)
               {
+                xref=(MagickOffsetType *) RelinquishMagickMemory(xref);
                 (void) CloseBlob(image);
                 return(MagickFalse);
               }
@@ -1973,6 +1975,7 @@
             pixel_info=RelinquishVirtualMemory(pixel_info);
             if (status == MagickFalse)
               {
+                xref=(MagickOffsetType *) RelinquishMagickMemory(xref);
                 (void) CloseBlob(image);
                 return(MagickFalse);
               }
@@ -2019,6 +2022,7 @@
             status=InjectImageBlob(image_info,image,image,"jpeg",exception);
             if (status == MagickFalse)
               {
+                xref=(MagickOffsetType *) RelinquishMagickMemory(xref);
                 (void) CloseBlob(image);
                 return(MagickFalse);
               }
@@ -2029,6 +2033,7 @@
             status=InjectImageBlob(image_info,image,image,"jp2",exception);
             if (status == MagickFalse)
               {
+                xref=(MagickOffsetType *) RelinquishMagickMemory(xref);
                 (void) CloseBlob(image);
                 return(MagickFalse);
               }
@@ -2047,10 +2052,7 @@
             length*=image->colorspace == CMYKColorspace ? 4UL : 3UL;
             pixel_info=AcquireVirtualMemory(length,sizeof(*pixels));
             if (pixel_info == (MemoryInfo *) NULL)
-              {
-                xref=(MagickOffsetType *) RelinquishMagickMemory(xref);
-                ThrowPDFException(ResourceLimitError,"MemoryAllocationFailed");
-              }
+              ThrowPDFException(ResourceLimitError,"MemoryAllocationFailed");
             pixels=(unsigned char *) GetVirtualMemoryBlob(pixel_info);
             /*
               Dump runoffset encoded pixels.
@@ -2090,6 +2092,7 @@
             pixel_info=RelinquishVirtualMemory(pixel_info);
             if (status == MagickFalse)
               {
+                xref=(MagickOffsetType *) RelinquishMagickMemory(xref);
                 (void) CloseBlob(image);
                 return(MagickFalse);
               }
@@ -2147,11 +2150,7 @@
               length=(size_t) number_pixels;
               pixel_info=AcquireVirtualMemory(length,sizeof(*pixels));
               if (pixel_info == (MemoryInfo *) NULL)
-                {
-                  xref=(MagickOffsetType *) RelinquishMagickMemory(xref);
-                  ThrowPDFException(ResourceLimitError,
-                    "MemoryAllocationFailed");
-                }
+                ThrowPDFException(ResourceLimitError,"MemoryAllocationFailed");
               pixels=(unsigned char *) GetVirtualMemoryBlob(pixel_info);
               /*
                 Dump Runlength encoded pixels.
@@ -2187,6 +2186,7 @@
               pixel_info=RelinquishVirtualMemory(pixel_info);
               if (status == MagickFalse)
                 {
+                  xref=(MagickOffsetType *) RelinquishMagickMemory(xref);
                   (void) CloseBlob(image);
                   return(MagickFalse);
                 }
@@ -2435,6 +2435,7 @@
               exception);
             if (status == MagickFalse)
               {
+                xref=(MagickOffsetType *) RelinquishMagickMemory(xref);
                 (void) CloseBlob(image);
                 return(MagickFalse);
               }
@@ -2445,6 +2446,7 @@
             status=InjectImageBlob(image_info,image,tile_image,"jp2",exception);
             if (status == MagickFalse)
               {
+                xref=(MagickOffsetType *) RelinquishMagickMemory(xref);
                 (void) CloseBlob(image);
                 return(MagickFalse);
               }
@@ -2496,6 +2498,7 @@
             pixel_info=RelinquishVirtualMemory(pixel_info);
             if (status == MagickFalse)
               {
+                xref=(MagickOffsetType *) RelinquishMagickMemory(xref);
                 (void) CloseBlob(image);
                 return(MagickFalse);
               }
@@ -2537,6 +2540,7 @@
               exception);
             if (status == MagickFalse)
               {
+                xref=(MagickOffsetType *) RelinquishMagickMemory(xref);
                 (void) CloseBlob(image);
                 return(MagickFalse);
               }
@@ -2547,6 +2551,7 @@
             status=InjectImageBlob(image_info,image,tile_image,"jp2",exception);
             if (status == MagickFalse)
               {
+                xref=(MagickOffsetType *) RelinquishMagickMemory(xref);
                 (void) CloseBlob(image);
                 return(MagickFalse);
               }
@@ -2602,6 +2607,7 @@
             pixel_info=RelinquishVirtualMemory(pixel_info);
             if (status == MagickFalse)
               {
+                xref=(MagickOffsetType *) RelinquishMagickMemory(xref);
                 (void) CloseBlob(image);
                 return(MagickFalse);
               }
@@ -2690,6 +2696,7 @@
               pixel_info=RelinquishVirtualMemory(pixel_info);
               if (status == MagickFalse)
                 {
+                  xref=(MagickOffsetType *) RelinquishMagickMemory(xref);
                   (void) CloseBlob(image);
                   return(MagickFalse);
                 }
@@ -2902,6 +2909,7 @@
             pixel_info=RelinquishVirtualMemory(pixel_info);
             if (status == MagickFalse)
               {
+                xref=(MagickOffsetType *) RelinquishMagickMemory(xref);
                 (void) CloseBlob(image);
                 return(MagickFalse);
               }
```
