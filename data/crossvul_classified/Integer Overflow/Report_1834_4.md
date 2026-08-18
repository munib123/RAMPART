# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 1834_4
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1834_4`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 29-71 of the vulnerable file.

#endif 

#define MAGICKWAND_IMPLEMENTATION  1

#if !defined(_MAGICKWAND_CONFIG_H)
# define _MAGICKWAND_CONFIG_H
# if !defined(vms) && !defined(macintosh)
#  include "MagickCore/magick-config.h"
# else
#  include "magick-config.h"
# endif
#if defined(MAGICKCORE__FILE_OFFSET_BITS) && !defined(_FILE_OFFSET_BITS)
# define _FILE_OFFSET_BITS MAGICKCORE__FILE_OFFSET_BITS
#endif
#if defined(_magickcore_const) && !defined(const)
# define const _magickcore_const
#endif
#if defined(_magickcore_inline) && !defined(inline)
# define inline _magickcore_inline
#endif
#if defined(_magickcore_restrict) && !defined(restrict)
# define restrict  _magickcore_restrict
#endif
# if defined(__cplusplus) || defined(c_plusplus)
#  undef inline
# endif
#endif

#if !defined(const)
#  define STDC
#endif

#if defined(__cplusplus) || defined(c_plusplus)
# define storage_class  c_class
#else
# define storage_class  class
#endif

#include <stdarg.h>
#include <stdio.h>
#if defined(MAGICKCORE_HAVE_SYS_STAT_H)
# include <sys/stat.h>
#endif
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -46,9 +46,6 @@
 #if defined(_magickcore_inline) && !defined(inline)
 # define inline _magickcore_inline
 #endif
-#if defined(_magickcore_restrict) && !defined(restrict)
-# define restrict  _magickcore_restrict
-#endif
 # if defined(__cplusplus) || defined(c_plusplus)
 #  undef inline
 # endif
@@ -76,6 +73,9 @@
 # if defined(MAGICKCORE_HAVE_STDLIB_H)
 #  include <stdlib.h>
 # endif
+#endif
+#if defined(_magickcore_restrict) && !defined(restrict)
+# define restrict  _magickcore_restrict
 #endif
 #if defined(MAGICKCORE_HAVE_STRING_H)
 # if !defined(STDC_HEADERS) && defined(MAGICKCORE_HAVE_MEMORY_H)
```
