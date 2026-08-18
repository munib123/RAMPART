# CrossVul Fix Pair: Missing Release of Resource after Effective Lifetime in c
**Pair ID:** 3103_1
**Vulnerability Class:** Missing Release of Resource after Effective Lifetime
**CWE:** CWE-772
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3103_1`)

## Vulnerability Information & PoC

## Description
Missing Release of Resource after Effective Lifetime - When a resource is not released after use, it can allow attackers to cause a denial of service by causing the allocation of resources without triggering their release.

## Vulnerable Code
```c
Lines 51-91 of the vulnerable file.

#include "magick/color-private.h"
#include "magick/colormap.h"
#include "magick/constitute.h"
#include "magick/exception.h"
#include "magick/exception-private.h"
#include "magick/geometry.h"
#include "magick/hashmap.h"
#include "magick/image.h"
#include "magick/image-private.h"
#include "magick/list.h"
#include "magick/magick.h"
#include "magick/memory_.h"
#include "magick/module.h"
#include "magick/monitor.h"
#include "magick/monitor-private.h"
#include "magick/option.h"
#include "magick/pixel-accessor.h"
#include "magick/profile.h"
#include "magick/property.h"
#include "magick/quantum-private.h"
#include "magick/static.h"
#include "magick/statistic.h"
#include "magick/string_.h"
#include "magick/string-private.h"
#include "magick/utility.h"
#include "magick/version-private.h"


/*
  Forward declarations.
*/
static MagickBooleanType
  WriteMPCImage(const ImageInfo *,Image *);


/*
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%                                                                             %
%                                                                             %
%                                                                             %
%   I s M P C                                                                 %
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -68,6 +68,7 @@
 #include "magick/profile.h"
 #include "magick/property.h"
 #include "magick/quantum-private.h"
+#include "magick/resource_.h"
 #include "magick/static.h"
 #include "magick/statistic.h"
 #include "magick/string_.h"
@@ -845,7 +846,9 @@
         /*
           Create image colormap.
         */
-        if (AcquireImageColormap(image,image->colors) == MagickFalse)
+        image->colormap=(PixelPacket *) AcquireQuantumMemory(image->colors+1,
+          sizeof(*image->colormap));
+        if (image->colormap == (PixelPacket *) NULL)
           ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
         if (image->colors != 0)
           {
@@ -934,12 +937,9 @@
     if ((image_info->ping != MagickFalse) && (image_info->number_scenes != 0))
       if (image->scene >= (image_info->scene+image_info->number_scenes-1))
         break;
-    status=SetImageExtent(image,image->columns,image->rows);
-    if (status == MagickFalse)
-      {
-        InheritException(exception,&image->exception);
-        return(DestroyImageList(image));
-      }
+    if ((AcquireMagickResource(WidthResource,image->columns) == MagickFalse) ||
+        (AcquireMagickResource(HeightResource,image->rows) == MagickFalse))
+      ThrowReaderException(ImageError,"WidthOrHeightExceedsLimit");
     /*
       Attach persistent pixel cache.
     */
```
