# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2678_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2678_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1-41 of the vulnerable file.

/*
 * Copyright (c) 1992, 1993, 1994, 1995, 1996
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

/*
 * Inline functions or macros to extract possibly-unaligned big-endian
 * integral values.
 */
#include "funcattrs.h"

/*
 * If we have versions of GCC or Clang that support an __attribute__
 * to say "if we're building with unsigned behavior sanitization,
 * don't complain about undefined behavior in this function", we
 * label these functions with that attribute - we *know* it's undefined
 * in the C standard, but we *also* know it does what we want with
 * the ISA we're targeting and the compiler we're using.
 *
 * For GCC 4.9.0 and later, we use __attribute__((no_sanitize_undefined));
 * pre-5.0 GCC doesn't have __has_attribute, and I'm not sure whether
 * GCC or Clang first had __attribute__((no_sanitize(XXX)).
 *
 * For Clang, we check for __attribute__((no_sanitize(XXX)) with
 * __has_attribute, as there are versions of Clang that support
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -18,6 +18,13 @@
  * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
  * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
  */
+
+/*
+ * For 8-bit values; provided for the sake of completeness.  Byte order
+ * isn't relevant, and alignment isn't an issue.
+ */
+#define EXTRACT_8BITS(p)	(*(p))
+#define EXTRACT_LE_8BITS(p)	(*(p))
 
 /*
  * Inline functions or macros to extract possibly-unaligned big-endian
@@ -226,7 +233,6 @@
  * Macros to extract possibly-unaligned little-endian integral values.
  * XXX - do loads on little-endian machines that support unaligned loads?
  */
-#define EXTRACT_LE_8BITS(p) (*(p))
 #define EXTRACT_LE_16BITS(p) \
 	((uint16_t)(((uint16_t)(*((const uint8_t *)(p) + 1)) << 8) | \
 	            ((uint16_t)(*((const uint8_t *)(p) + 0)) << 0)))
```
