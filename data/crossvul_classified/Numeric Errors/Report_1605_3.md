# CrossVul Fix Pair: Numeric Errors in cpp
**Pair ID:** 1605_3
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1605_3`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```cpp
Lines 4-44 of the vulnerable file.

LibRaw is free software; you can redistribute it and/or modify
it under the terms of the one of three licenses as you choose:

1. GNU LESSER GENERAL PUBLIC LICENSE version 2.1
   (See file LICENSE.LGPL provided in LibRaw distribution archive for details).

2. COMMON DEVELOPMENT AND DISTRIBUTION LICENSE (CDDL) Version 1.0
   (See file LICENSE.CDDL provided in LibRaw distribution archive for details).

3. LibRaw Software License 27032010
   (See file LICENSE.LibRaw.pdf provided in LibRaw distribution archive for details).

   This file is generated from Dave Coffin's dcraw.c
   dcraw.c -- Dave Coffin's raw photo decoder
   Copyright 1997-2010 by Dave Coffin, dcoffin a cybercom o net

   Look into dcraw homepage (probably http://cybercom.net/~dcoffin/dcraw/)
   for more information
*/

#include <math.h>
#define CLASS LibRaw::
#include "libraw/libraw_types.h"
#define LIBRAW_LIBRARY_BUILD
#define LIBRAW_IO_REDEFINED
#include "libraw/libraw.h"
#include "internal/defines.h"
#include "internal/var_defines.h"
int CLASS fcol (int row, int col)
{
  static const char filter[16][16] =
  { { 2,1,1,3,2,3,2,0,3,2,3,0,1,2,1,0 },
    { 0,3,0,2,0,1,3,1,0,1,1,2,0,3,3,2 },
    { 2,3,3,2,3,1,1,3,3,1,2,1,2,0,0,3 },
    { 0,1,0,1,0,2,0,2,2,0,3,0,1,3,2,1 },
    { 3,1,1,2,0,1,0,2,1,3,1,3,0,1,3,0 },
    { 2,0,0,3,3,2,3,1,2,0,2,0,3,2,2,1 },
    { 2,3,3,1,2,1,2,1,2,1,1,2,3,0,0,1 },
    { 1,0,0,2,3,0,0,3,0,3,0,3,2,1,2,3 },
    { 2,3,3,1,1,2,1,0,3,2,3,0,2,3,1,3 },
    { 1,0,2,0,3,0,3,2,0,1,1,2,0,1,0,2 },
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -21,6 +21,7 @@
    for more information
 */
 
+#line 261 "dcraw/dcraw.c"
 #include <math.h>
 #define CLASS LibRaw::
 #include "libraw/libraw_types.h"
@@ -29,6 +30,7 @@
 #include "libraw/libraw.h"
 #include "internal/defines.h"
 #include "internal/var_defines.h"
+#line 272 "dcraw/dcraw.c"
 int CLASS fcol (int row, int col)
 {
   static const char filter[16][16] =
@@ -75,6 +77,7 @@
 }
 #define strcasestr my_strcasestr
 #endif
+#line 340 "dcraw/dcraw.c"
 ushort CLASS sget2 (uchar *s)
 {
   if (order == 0x4949)		/* "II" means little-endian */
@@ -564,10 +567,12 @@
 #endif
   FORC(2) free (huff[c]);
 }
+#line 841 "dcraw/dcraw.c"
 
 int CLASS ljpeg_start (struct jhead *jh, int info_only)
 {
-  int c, tag, len;
+  int c, tag;
+  ushort len;
   uchar data[0x10000];
   const uchar *dp;
 
@@ -1153,6 +1158,7 @@
     if (tail[i]) nz++;
   return nz > 20;
 }
+#line 1436 "dcraw/dcraw.c"
 void CLASS ppm_thumb()
 {
   char *thumb;
@@ -2976,6 +2982,7 @@
 #endif
 #endif
 }
+#line 3983 "dcraw/dcraw.c"
 void CLASS crop_masked_pixels()
 {
   int row, col;
@@ -3081,6 +3088,7 @@
   RUN_CALLBACK(LIBRAW_PROGRESS_REMOVE_ZEROES,1,2);
 #endif
 }
+#line 4254 "dcraw/dcraw.c"
 void CLASS gamma_curve (double pwr, double ts, int mode, int imax)
 {
   int i;
@@ -4790,6 +4798,7 @@
     fseek (ifp, save, SEEK_SET);
   }
 }
+#line 5968 "dcraw/dcraw.c"
 void CLASS parse_makernote (int base, int uptag)
 {
   static const uchar xlat[2][256] = {
@@ -5349,6 +5358,7 @@
     fseek (ifp, save, SEEK_SET);
   }
 }
+#line 6533 "dcraw/dcraw.c"
 int CLASS parse_tiff_ifd (int base)
 {
   unsigned entries, tag, type, len, plen=16, save;
@@ -6648,6 +6658,7 @@
     data_offset = get4();
   }
 }
+#line 7936 "dcraw/dcraw.c"
 
 /*
    All matrices are from Adobe DNG Converter unless otherwise noted.
@@ -8923,6 +8934,7 @@
 }
 
 
+#line 10303 "dcraw/dcraw.c"
 void CLASS convert_to_rgb()
 {
 #ifndef LIBRAW_LIBRARY_BUILD
@@ -9153,6 +9165,7 @@
   if (flip & 1) col = iwidth  - 1 - col;
   return row * iwidth + col;
 }
+#line 10559 "dcraw/dcraw.c"
 void CLASS tiff_set (ushort *ntag,
 	ushort tag, ushort type, int count, int val)
 {
```
