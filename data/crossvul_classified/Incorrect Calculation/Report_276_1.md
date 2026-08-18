# CrossVul Fix Pair: Incorrect Calculation in c
**Pair ID:** 276_1
**Vulnerability Class:** Incorrect Calculation
**CWE:** CWE-682
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `276_1`)

## Vulnerability Information & PoC

## Description
Incorrect Calculation - When product performs a security-critical calculation incorrectly, it might lead to incorrect resource allocations, incorrect privilege assignments, or failed comparisons among other things.

## Vulnerable Code
```c
Lines 1-22 of the vulnerable file.

/* This file is part of libmspack.
 * (C) 2003-2011 Stuart Caie.
 *
 * libmspack is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License (LGPL) version 2.1
 *
 * For further details, see the file COPYING.LIB distributed with libmspack
 */

/* CHM decompression implementation */

#include <system.h>
#include <chm.h>

/* prototypes */
static struct mschmd_header * chmd_open(
  struct mschm_decompressor *base, const char *filename);
static struct mschmd_header * chmd_fast_open(
  struct mschm_decompressor *base, const char *filename);
static struct mschmd_header *chmd_real_open(
  struct mschm_decompressor *base, const char *filename, int entire);
static void chmd_close(
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,5 +1,5 @@
 /* This file is part of libmspack.
- * (C) 2003-2011 Stuart Caie.
+ * (C) 2003-2018 Stuart Caie.
  *
  * libmspack is free software; you can redistribute it and/or modify it under
  * the terms of the GNU Lesser General Public License (LGPL) version 2.1
@@ -397,7 +397,7 @@
     D(("first pmgl chunk is after last pmgl chunk"))
     return MSPACK_ERR_DATAFORMAT;
   }
-  if (chm->index_root != 0xFFFFFFFF && chm->index_root > chm->num_chunks) {
+  if (chm->index_root != 0xFFFFFFFF && chm->index_root >= chm->num_chunks) {
     D(("index_root outside valid range"))
     return MSPACK_ERR_DATAFORMAT;
   }
@@ -447,7 +447,10 @@
     while (num_entries--) {
       READ_ENCINT(name_len);
       if (name_len > (unsigned int) (end - p)) goto chunk_end;
+      /* consider blank filenames to be an error */
+      if (name_len == 0) goto chunk_end;
       name = p; p += name_len;
+
       READ_ENCINT(section);
       READ_ENCINT(offset);
       READ_ENCINT(length);
@@ -622,7 +625,7 @@
     unsigned char *buf;
 
     /* check arguments - most are already checked by chmd_fast_find */
-    if (chunk_num > chm->num_chunks) return NULL;
+    if (chunk_num >= chm->num_chunks) return NULL;
     
     /* ensure chunk cache is available */
     if (!chm->chunk_cache) {
```
