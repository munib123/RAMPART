# CrossVul Fix Pair: Divide By Zero in c
**Pair ID:** 153_1
**Vulnerability Class:** Divide By Zero
**CWE:** CWE-369
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `153_1`)

## Vulnerability Information & PoC

## Description
Divide By Zero - This weakness typically occurs when an unexpected value is provided to the product, or if an error occurs that is not properly detected.

## Vulnerable Code
```c
Lines 1-29 of the vulnerable file.

/*
 * rdbmp.c
 *
 * This file was part of the Independent JPEG Group's software:
 * Copyright (C) 1994-1996, Thomas G. Lane.
 * Modified 2009-2010 by Guido Vollbeding.
 * libjpeg-turbo Modifications:
 * Modified 2011 by Siarhei Siamashka.
 * Copyright (C) 2015, 2017, D. R. Commander.
 * For conditions of distribution and use, see the accompanying README.ijg
 * file.
 *
 * This file contains routines to read input images in Microsoft "BMP"
 * format (MS Windows 3.x, OS/2 1.x, and OS/2 2.x flavors).
 * Currently, only 8-bit and 24-bit images are supported, not 1-bit or
 * 4-bit (feeding such low-depth images into JPEG would be silly anyway).
 * Also, we don't support RLE-compressed files.
 *
 * These routines may need modification for non-Unix environments or
 * specialized applications.  As they stand, they assume input from
 * an ordinary stdio stream.  They further assume that reading begins
 * at the start of the file; start_input may need work if the
 * user interface has already read some data (e.g., to determine that
 * the file is indeed BMP format).
 *
 * This code contributed by James Arthur Boucher.
 */

#include "cmyk.h"
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -6,7 +6,7 @@
  * Modified 2009-2010 by Guido Vollbeding.
  * libjpeg-turbo Modifications:
  * Modified 2011 by Siarhei Siamashka.
- * Copyright (C) 2015, 2017, D. R. Commander.
+ * Copyright (C) 2015, 2017-2018, D. R. Commander.
  * For conditions of distribution and use, see the accompanying README.ijg
  * file.
  *
@@ -623,6 +623,12 @@
     }
   }
 
+  /* Ensure that biWidth * cinfo->input_components doesn't exceed the maximum
+     value of the JDIMENSION type.  This is only a danger with BMP files, since
+     their width and height fields are 32-bit integers. */
+  if ((unsigned long long)biWidth *
+      (unsigned long long)cinfo->input_components > 0xFFFFFFFFULL)
+    ERREXIT(cinfo, JERR_WIDTH_OVERFLOW);
   /* Allocate one-row buffer for returned data */
   source->pub.buffer = (*cinfo->mem->alloc_sarray)
     ((j_common_ptr)cinfo, JPOOL_IMAGE,
```
