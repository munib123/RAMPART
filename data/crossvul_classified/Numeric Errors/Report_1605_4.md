# CrossVul Fix Pair: Numeric Errors in cpp
**Pair ID:** 1605_4
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1605_4`)

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

#line 4090 "dcraw/dcraw.c"
#include <math.h>
#define CLASS LibRaw::
#include "libraw/libraw_types.h"
#define LIBRAW_LIBRARY_BUILD
#include "libraw/libraw.h"
#include "internal/defines.h"
#include "internal/var_defines.h"
#line 4101 "dcraw/dcraw.c"
/*
   Seach from the current directory up to the root looking for
   a ".badpixels" file, and fix those pixels now.
 */
void CLASS bad_pixels (const char *cfname)
{
  FILE *fp=NULL;
#ifndef LIBRAW_LIBRARY_BUILD
  char *fname, *cp, line[128];
  int len, time, row, col, r, c, rad, tot, n, fixed=0;
#else
  char *cp, line[128];
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -21,7 +21,7 @@
    for more information
 */
 
-#line 4090 "dcraw/dcraw.c"
+#line 4091 "dcraw/dcraw.c"
 #include <math.h>
 #define CLASS LibRaw::
 #include "libraw/libraw_types.h"
@@ -29,7 +29,7 @@
 #include "libraw/libraw.h"
 #include "internal/defines.h"
 #include "internal/var_defines.h"
-#line 4101 "dcraw/dcraw.c"
+#line 4102 "dcraw/dcraw.c"
 /*
    Seach from the current directory up to the root looking for
    a ".badpixels" file, and fix those pixels now.
@@ -54,7 +54,7 @@
 #endif
   if (cfname)
     fp = fopen (cfname, "r");
-#line 4151 "dcraw/dcraw.c"
+#line 4152 "dcraw/dcraw.c"
   if (!fp)
       {
 #ifdef LIBRAW_LIBRARY_BUILD
@@ -154,7 +154,7 @@
   RUN_CALLBACK(LIBRAW_PROGRESS_DARK_FRAME,1,2);
 #endif
 }
-#line 10213 "dcraw/dcraw.c"
+#line 10214 "dcraw/dcraw.c"
 #ifndef NO_LCMS
 void CLASS apply_profile (const char *input, const char *output)
 {
```
