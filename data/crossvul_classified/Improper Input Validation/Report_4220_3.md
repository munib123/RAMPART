# CrossVul Fix Pair: Improper Input Validation in cpp
**Pair ID:** 4220_3
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4220_3`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```cpp
Lines 7-47 of the vulnerable file.


1. GNU LESSER GENERAL PUBLIC LICENSE version 2.1
   (See file LICENSE.LGPL provided in LibRaw distribution archive for details).

2. COMMON DEVELOPMENT AND DISTRIBUTION LICENSE (CDDL) Version 1.0
   (See file LICENSE.CDDL provided in LibRaw distribution archive for details).

 */

#include "../../internal/libraw_cxx_defs.h"

void LibRaw::kodak_thumb_loader()
{
  INT64 est_datasize =
      T.theight * T.twidth / 3; // is 0.3 bytes per pixel good estimate?
  if (ID.toffset < 0)
    throw LIBRAW_EXCEPTION_IO_CORRUPT;

  if (ID.toffset + est_datasize > ID.input->size() + THUMB_READ_BEYOND)
    throw LIBRAW_EXCEPTION_IO_EOF;

  // some kodak cameras
  ushort s_height = S.height, s_width = S.width, s_iwidth = S.iwidth,
         s_iheight = S.iheight;
  ushort s_flags = libraw_internal_data.unpacker_data.load_flags;
  libraw_internal_data.unpacker_data.load_flags = 12;
  int s_colors = P1.colors;
  unsigned s_filters = P1.filters;
  ushort(*s_image)[4] = imgdata.image;

  S.height = T.theight;
  S.width = T.twidth;
  P1.filters = 0;

  if (thumb_load_raw == &LibRaw::kodak_ycbcr_load_raw)
  {
    S.height += S.height & 1;
    S.width += S.width & 1;
  }

  imgdata.image =
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -24,6 +24,12 @@
 
   if (ID.toffset + est_datasize > ID.input->size() + THUMB_READ_BEYOND)
     throw LIBRAW_EXCEPTION_IO_EOF;
+
+  if(INT64(T.theight) * INT64(T.twidth) > 1024ULL * 1024ULL * LIBRAW_MAX_THUMBNAIL_MB)
+      throw LIBRAW_EXCEPTION_IO_CORRUPT;
+
+  if (INT64(T.theight) * INT64(T.twidth) < 64ULL)
+      throw LIBRAW_EXCEPTION_IO_CORRUPT;
 
   // some kodak cameras
   ushort s_height = S.height, s_width = S.width, s_iwidth = S.iwidth,
```
