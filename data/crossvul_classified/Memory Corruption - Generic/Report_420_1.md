# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 420_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `420_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 1-22 of the vulnerable file.

/* This file is part of libmspack.
 * (C) 2003-2004 Stuart Caie.
 *
 * libmspack is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License (LGPL) version 2.1
 *
 * For further details, see the file COPYING.LIB distributed with libmspack
 */

#ifndef MSPACK_CAB_H
#define MSPACK_CAB_H 1

#include <mszip.h>
#include <qtm.h>
#include <lzx.h>

/* generic CAB definitions */

/* structure offsets */
#define cfhead_Signature         (0x00)
#define cfhead_CabinetSize       (0x08)
#define cfhead_FileOffset        (0x10)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,5 +1,5 @@
 /* This file is part of libmspack.
- * (C) 2003-2004 Stuart Caie.
+ * (C) 2003-2018 Stuart Caie.
  *
  * libmspack is free software; you can redistribute it and/or modify it under
  * the terms of the GNU Lesser General Public License (LGPL) version 2.1
@@ -70,6 +70,14 @@
 #define CAB_BLOCKMAX (32768)
 #define CAB_INPUTMAX (CAB_BLOCKMAX+6144)
 
+/* input buffer needs to be CAB_INPUTMAX + 1 byte to allow for max-sized block
+ * plus 1 trailer byte added by cabd_sys_read_block() for Quantum alignment.
+ *
+ * When MSCABD_PARAM_SALVAGE is set, block size is not checked so can be
+ * up to 65535 bytes, so max input buffer size needed is 65535 + 1
+ */
+#define CAB_INPUTBUF (65535 + 1)
+
 /* There are no more than 65535 data blocks per folder, so a folder cannot
  * be more than 32768*65535 bytes in length. As files cannot span more than
  * one folder, this is also their max offset, length and offset+length limit.
@@ -101,7 +109,7 @@
   struct mspack_file *infh;          /* input file handle                    */
   struct mspack_file *outfh;         /* output file handle                   */
   unsigned char *i_ptr, *i_end;      /* input data consumed, end             */
-  unsigned char input[CAB_INPUTMAX]; /* one input block of data              */
+  unsigned char input[CAB_INPUTBUF]; /* one input block of data              */
 };
 
 struct mscab_decompressor_p {
```
