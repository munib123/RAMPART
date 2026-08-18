# CrossVul Fix Pair: Improper Input Validation in cpp
**Pair ID:** 4220_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4220_2`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```cpp
Lines 14-54 of the vulnerable file.


#include "../../internal/libraw_cxx_defs.h"

libraw_processed_image_t *LibRaw::dcraw_make_mem_thumb(int *errcode)
{
  if (!T.thumb)
  {
    if (!ID.toffset && !(imgdata.thumbnail.tlength > 0 &&
                         load_raw == &LibRaw::broadcom_load_raw) // RPi
    )
    {
      if (errcode)
        *errcode = LIBRAW_NO_THUMBNAIL;
    }
    else
    {
      if (errcode)
        *errcode = LIBRAW_OUT_OF_ORDER_CALL;
    }
    return NULL;
  }

  if (T.tformat == LIBRAW_THUMBNAIL_BITMAP)
  {
    libraw_processed_image_t *ret = (libraw_processed_image_t *)::malloc(
        sizeof(libraw_processed_image_t) + T.tlength);

    if (!ret)
    {
      if (errcode)
        *errcode = ENOMEM;
      return NULL;
    }

    memset(ret, 0, sizeof(libraw_processed_image_t));
    ret->type = LIBRAW_IMAGE_BITMAP;
    ret->height = T.theight;
    ret->width = T.twidth;
    ret->colors = 3;
    ret->bits = 8;
    ret->data_size = T.tlength;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -31,6 +31,20 @@
         *errcode = LIBRAW_OUT_OF_ORDER_CALL;
     }
     return NULL;
+  }
+
+  if (T.tlength < 64u)
+  {
+      if (errcode)
+          *errcode = EINVAL;
+      return NULL;
+  }
+
+  if (INT64(T.tlength) > 1024ULL * 1024ULL * LIBRAW_MAX_THUMBNAIL_MB)
+  {
+      if (errcode)
+          *errcode = LIBRAW_TOO_BIG;
+      return NULL;
   }
 
   if (T.tformat == LIBRAW_THUMBNAIL_BITMAP)
```
