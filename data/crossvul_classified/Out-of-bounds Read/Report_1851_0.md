# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 1851_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1851_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 243-283 of the vulnerable file.


  MagickBooleanType
    status;

  MagickSizeType
    number_pixels;

  register Quantum
    *q;

  register ssize_t
    i,
    x;

  register unsigned char
    *p;

  size_t
    bytes_per_line,
    extent,
    length;

  ssize_t
    count,
    y;

  SUNInfo
    sun_info;

  unsigned char
    *sun_data,
    *sun_pixels;

  /*
    Open image file.
  */
  assert(image_info != (const ImageInfo *) NULL);
  assert(image_info->signature == MagickSignature);
  if (image_info->debug != MagickFalse)
    (void) LogMagickEvent(TraceEvent,GetMagickModule(),"%s",
      image_info->filename);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -260,6 +260,7 @@
   size_t
     bytes_per_line,
     extent,
+    height,
     length;
 
   ssize_t
@@ -425,33 +426,23 @@
     count=(ssize_t) ReadBlob(image,sun_info.length,sun_data);
     if (count != (ssize_t) sun_info.length)
       ThrowReaderException(CorruptImageError,"UnableToReadImageData");
-    sun_pixels=sun_data;
-    bytes_per_line=0;
+    height=sun_info.height;
+    if ((height == 0) || (sun_info.width == 0) || (sun_info.depth == 0) ||
+        ((bytes_per_line/sun_info.depth) != sun_info.width))
+      ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
+    bytes_per_line+=15;
+    bytes_per_line<<=1;
+    if ((bytes_per_line >> 1) != (sun_info.width*sun_info.depth+15))
+      ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
+    bytes_per_line>>=4;
+    sun_pixels=(unsigned char *) AcquireQuantumMemory(height,
+      bytes_per_line*sizeof(*sun_pixels));
+    if (sun_pixels == (unsigned char *) NULL)
+      ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
     if (sun_info.type == RT_ENCODED)
-      {
-        size_t
-          height;
-
-        /*
-          Read run-length encoded raster pixels.
-        */
-        height=sun_info.height;
-        if ((height == 0) || (sun_info.width == 0) || (sun_info.depth == 0) ||
-            ((bytes_per_line/sun_info.depth) != sun_info.width))
-          ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
-        bytes_per_line+=15;
-        bytes_per_line<<=1;
-        if ((bytes_per_line >> 1) != (sun_info.width*sun_info.depth+15))
-          ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
-        bytes_per_line>>=4;
-        sun_pixels=(unsigned char *) AcquireQuantumMemory(height,
-          bytes_per_line*sizeof(*sun_pixels));
-        if (sun_pixels == (unsigned char *) NULL)
-          ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
-        (void) DecodeImage(sun_data,sun_info.length,sun_pixels,bytes_per_line*
-          height);
-        sun_data=(unsigned char *) RelinquishMagickMemory(sun_data);
-      }
+      (void) DecodeImage(sun_data,sun_info.length,sun_pixels,bytes_per_line*
+        height);
+    sun_data=(unsigned char *) RelinquishMagickMemory(sun_data);
     /*
       Convert SUN raster image to pixel packets.
     */
```
