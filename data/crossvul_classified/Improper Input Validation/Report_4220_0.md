# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 4220_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4220_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 3-43 of the vulnerable file.

 * Copyright 2008-2020 LibRaw LLC (info@libraw.org)
 * Created: Sat Mar  8 , 2008
 * LibRaw error codes
LibRaw is free software; you can redistribute it and/or modify
it under the terms of the one of two licenses as you choose:

1. GNU LESSER GENERAL PUBLIC LICENSE version 2.1
   (See file LICENSE.LGPL provided in LibRaw distribution archive for details).

2. COMMON DEVELOPMENT AND DISTRIBUTION LICENSE (CDDL) Version 1.0
   (See file LICENSE.CDDL provided in LibRaw distribution archive for details).

 */

#ifndef _LIBRAW_ERRORS_H
#define _LIBRAW_ERRORS_H

#define LIBRAW_DEFAULT_ADJUST_MAXIMUM_THRESHOLD 0.75
#define LIBRAW_DEFAULT_AUTO_BRIGHTNESS_THRESHOLD 0.01
/* limit allocation size, default is 2Gb */
#define LIBRAW_MAX_ALLOC_MB_DEFAULT 2048L

/* Check if enough file space exists before tag read */
#ifndef LIBRAW_NO_IOSPACE_CHECK
#define LIBRAW_IOSPACE_CHECK
#endif
#ifndef LIBRAW_NO_CR3_MEMPOOL
#define LIBRAW_CR3_MEMPOOL
#endif


/* LibRaw uses own memory pool management, with LIBRAW_MSIZE (512)
entries. It is enough for parsing/decoding non-damaged files, but
may overflow on specially crafted files (eg. with many string values
like XMP blocks.
LIBRAW_MEMPOOL_CHECK define will result in error on pool overflow */
#ifndef LIBRAW_NO_MEMPOOL_CHECK
#define LIBRAW_MEMPOOL_CHECK
#endif

#define LIBRAW_MAX_METADATA_BLOCKS 1024
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -20,7 +20,14 @@
 #define LIBRAW_DEFAULT_ADJUST_MAXIMUM_THRESHOLD 0.75
 #define LIBRAW_DEFAULT_AUTO_BRIGHTNESS_THRESHOLD 0.01
 /* limit allocation size, default is 2Gb */
+#ifndef LIBRAW_MAX_ALLOC_MB_DEFAULT
 #define LIBRAW_MAX_ALLOC_MB_DEFAULT 2048L
+#endif
+
+/* limit thumbnail size, default is 512Mb*/
+#ifndef LIBRAW_MAX_THUMBNAIL_MB
+#define LIBRAW_MAX_THUMBNAIL_MB 512L
+#endif
 
 /* Check if enough file space exists before tag read */
 #ifndef LIBRAW_NO_IOSPACE_CHECK
```
