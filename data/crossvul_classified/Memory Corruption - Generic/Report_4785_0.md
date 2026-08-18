# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 4785_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4785_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 46-86 of the vulnerable file.

#include "magick/blob.h"
#include "magick/blob-private.h"
#include "magick/cache.h"
#include "magick/color.h"
#include "magick/color-private.h"
#include "magick/colormap.h"
#include "magick/colorspace.h"
#include "magick/colorspace-private.h"
#include "magick/constitute.h"
#include "magick/draw.h"
#include "magick/enhance.h"
#include "magick/exception.h"
#include "magick/exception-private.h"
#include "magick/geometry.h"
#include "magick/image.h"
#include "magick/image-private.h"
#include "magick/list.h"
#include "magick/log.h"
#include "magick/magick.h"
#include "magick/memory_.h"
#include "magick/module.h"
#include "magick/monitor.h"
#include "magick/monitor-private.h"
#include "magick/option.h"
#include "magick/pixel-accessor.h"
#include "magick/pixel-private.h"
#include "magick/profile.h"
#include "magick/property.h"
#include "magick/quantum.h"
#include "magick/quantum-private.h"
#include "magick/resize.h"
#include "magick/resource_.h"
#include "magick/semaphore.h"
#include "magick/splay-tree.h"
#include "magick/static.h"
#include "magick/statistic.h"
#include "magick/string_.h"
#include "magick/string-private.h"
#include "magick/thread_.h"
#include "magick/token.h"
#include "magick/utility.h"
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -63,6 +63,7 @@
 #include "magick/log.h"
 #include "magick/magick.h"
 #include "magick/memory_.h"
+#include "magick/memory-private.h"
 #include "magick/module.h"
 #include "magick/monitor.h"
 #include "magick/monitor-private.h"
@@ -1909,14 +1910,13 @@
           }
         (void) SetImageStorageClass(image,DirectClass);
         number_pixels=(MagickSizeType) columns*rows;
-        if ((number_pixels*sizeof(uint32)) != (MagickSizeType) ((size_t)
-            (number_pixels*sizeof(uint32))))
+        if (HeapOverflowSanityCheck(rows,sizeof(*tile_pixels)) != MagickFalse)
           {
             TIFFClose(tiff);
             ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
           }
-        tile_pixels=(uint32 *) AcquireQuantumMemory(number_pixels,
-          sizeof(*tile_pixels));
+        tile_pixels=(uint32 *) AcquireQuantumMemory(columns,
+          rows*sizeof(*tile_pixels));
         if (tile_pixels == (uint32 *) NULL)
           {
             TIFFClose(tiff);
@@ -2018,14 +2018,13 @@
           Convert TIFF image to DirectClass MIFF image.
         */
         number_pixels=(MagickSizeType) image->columns*image->rows;
-        if ((number_pixels*sizeof(uint32)) != (MagickSizeType) ((size_t)
-            (number_pixels*sizeof(uint32))))
+        if (HeapOverflowSanityCheck(image->rows,sizeof(*pixels)) != MagickFalse)
           {
             TIFFClose(tiff);
             ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
           }
         pixel_info=AcquireVirtualMemory(image->columns,image->rows*
-          sizeof(uint32));
+          sizeof(*pixels));
         if (pixel_info == (MemoryInfo *) NULL)
           {
             TIFFClose(tiff);
```
