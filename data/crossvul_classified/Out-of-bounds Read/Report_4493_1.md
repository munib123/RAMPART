# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 4493_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4493_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 8-48 of the vulnerable file.

 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE AUTHORS AND
 * CONTRIBUTORS ACCEPT NO RESPONSIBILITY IN ANY CONCEIVABLE MANNER.
 *
 ************************************************************************/

/*************************************************************************
 * Include files
 */

#if defined(HAVE_CONFIG_H)
#include <config.h>
#endif
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "triodef.h"
#include "triostr.h"
#if defined(TRIO_FUNC_TO_LONG_DOUBLE)
#define USE_MATH
#endif
#if defined(USE_MATH)
#include <math.h>
#endif

/*************************************************************************
 * Definitions
 */

#if !defined(TRIO_PUBLIC_STRING)
#define TRIO_PUBLIC_STRING TRIO_PUBLIC
#endif
#if !defined(TRIO_PRIVATE_STRING)
#define TRIO_PRIVATE_STRING TRIO_PRIVATE
#endif

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -25,6 +25,7 @@
 #include <assert.h>
 #include <stdlib.h>
 #include <string.h>
+#include <limits.h>
 #include <ctype.h>
 #include "triodef.h"
 #include "triostr.h"
@@ -328,7 +329,7 @@
 
 TRIO_PUBLIC_STRING size_t trio_length TRIO_ARGS1((string), TRIO_CONST char* string)
 {
-	return strlen(string);
+	return trio_length_max(string, INT_MAX);
 }
 
 #endif
```
