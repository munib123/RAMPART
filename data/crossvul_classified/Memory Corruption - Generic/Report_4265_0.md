# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 4265_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4265_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 57-97 of the vulnerable file.

#ifdef HAVE_WCHAR_H
#include <wchar.h>
#endif
#if defined(_WIN32) && !defined(__CYGWIN__)
#include <windows.h>
#include <locale.h>
#endif

#include "archive_endian.h"
#include "archive_private.h"
#include "archive_string.h"
#include "archive_string_composition.h"

#if !defined(HAVE_WMEMCPY) && !defined(wmemcpy)
#define wmemcpy(a,b,i)  (wchar_t *)memcpy((a), (b), (i) * sizeof(wchar_t))
#endif

#if !defined(HAVE_WMEMMOVE) && !defined(wmemmove)
#define wmemmove(a,b,i)  (wchar_t *)memmove((a), (b), (i) * sizeof(wchar_t))
#endif

struct archive_string_conv {
	struct archive_string_conv	*next;
	char				*from_charset;
	char				*to_charset;
	unsigned			 from_cp;
	unsigned			 to_cp;
	/* Set 1 if from_charset and to_charset are the same. */
	int				 same;
	int				 flag;
#define SCONV_TO_CHARSET	1	/* MBS is being converted to specified
					 * charset. */
#define SCONV_FROM_CHARSET	(1<<1)	/* MBS is being converted from
					 * specified charset. */
#define SCONV_BEST_EFFORT 	(1<<2)	/* Copy at least ASCII code. */
#define SCONV_WIN_CP	 	(1<<3)	/* Use Windows API for converting
					 * MBS. */
#define SCONV_UTF8_LIBARCHIVE_2 (1<<4)	/* Incorrect UTF-8 made by libarchive
					 * 2.x in the wrong assumption. */
#define SCONV_NORMALIZATION_C	(1<<6)	/* Need normalization to be Form C.
					 * Before UTF-8 characters are actually
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -74,6 +74,9 @@
 #if !defined(HAVE_WMEMMOVE) && !defined(wmemmove)
 #define wmemmove(a,b,i)  (wchar_t *)memmove((a), (b), (i) * sizeof(wchar_t))
 #endif
+
+#undef max
+#define max(a, b)       ((a)>(b)?(a):(b))
 
 struct archive_string_conv {
 	struct archive_string_conv	*next;
@@ -804,7 +807,8 @@
 			as->s[as->length] = '\0';
 			/* Re-allocate buffer for MBS. */
 			if (archive_string_ensure(as,
-			    as->length + len * 2 + 1) == NULL)
+			    as->length + max(len * 2,
+			    (size_t)MB_CUR_MAX) + 1) == NULL)
 				return (-1);
 			p = as->s + as->length;
 			end = as->s + as->buffer_length - MB_CUR_MAX -1;
@@ -3446,7 +3450,8 @@
 			as->length = p - as->s;
 			/* Re-allocate buffer for MBS. */
 			if (archive_string_ensure(as,
-			    as->length + len * 2 + 1) == NULL)
+			    as->length + max(len * 2,
+			    (size_t)MB_CUR_MAX) + 1) == NULL)
 				return (-1);
 			p = as->s + as->length;
 			end = as->s + as->buffer_length - MB_CUR_MAX -1;
```
