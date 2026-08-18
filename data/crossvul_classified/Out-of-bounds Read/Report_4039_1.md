# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 4039_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4039_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1-28 of the vulnerable file.

/*
 * rdppm.c
 *
 * This file was part of the Independent JPEG Group's software:
 * Copyright (C) 1991-1997, Thomas G. Lane.
 * Modified 2009 by Bill Allombert, Guido Vollbeding.
 * libjpeg-turbo Modifications:
 * Copyright (C) 2015-2017, D. R. Commander.
 * For conditions of distribution and use, see the accompanying README.ijg
 * file.
 *
 * This file contains routines to read input images in PPM/PGM format.
 * The extended 2-byte-per-sample raw PPM/PGM formats are supported.
 * The PBMPLUS library is NOT required to compile this software
 * (but it is highly useful as a set of PPM image manipulation programs).
 *
 * These routines may need modification for non-Unix environments or
 * specialized applications.  As they stand, they assume input from
 * an ordinary stdio stream.  They further assume that reading begins
 * at the start of the file; start_input may need work if the
 * user interface has already read some data (e.g., to determine that
 * the file is indeed PPM format).
 */

#include "cmyk.h"
#include "cdjpeg.h"             /* Common decls for cjpeg/djpeg applications */

#ifdef PPM_SUPPORTED
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5,7 +5,7 @@
  * Copyright (C) 1991-1997, Thomas G. Lane.
  * Modified 2009 by Bill Allombert, Guido Vollbeding.
  * libjpeg-turbo Modifications:
- * Copyright (C) 2015-2017, D. R. Commander.
+ * Copyright (C) 2015-2017, 2020, D. R. Commander.
  * For conditions of distribution and use, see the accompanying README.ijg
  * file.
  *
@@ -720,7 +720,7 @@
     /* On 16-bit-int machines we have to be careful of maxval = 65535 */
     source->rescale = (JSAMPLE *)
       (*cinfo->mem->alloc_small) ((j_common_ptr)cinfo, JPOOL_IMAGE,
-                                  (size_t)(((long)maxval + 1L) *
+                                  (size_t)(((long)MAX(maxval, 255) + 1L) *
                                            sizeof(JSAMPLE)));
     half_maxval = maxval / 2;
     for (val = 0; val <= (long)maxval; val++) {
```
