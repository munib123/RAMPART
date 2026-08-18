# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 444_1
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `444_1`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 48-88 of the vulnerable file.

# endif
# ifdef URI_ENABLE_UNICODE
#  define URI_PASS_UNICODE 1
#  include "UriQuery.c"
#  undef URI_PASS_UNICODE
# endif
#else
# ifdef URI_PASS_ANSI
#  include <uriparser/UriDefsAnsi.h>
# else
#  include <uriparser/UriDefsUnicode.h>
#  include <wchar.h>
# endif



#ifndef URI_DOXYGEN
# include <uriparser/Uri.h>
# include "UriCommon.h"
#endif



static int URI_FUNC(ComposeQueryEngine)(URI_CHAR * dest,
		const URI_TYPE(QueryList) * queryList,
		int maxChars, int * charsWritten, int * charsRequired,
		UriBool spaceToPlus, UriBool normalizeBreaks);

static UriBool URI_FUNC(AppendQueryItem)(URI_TYPE(QueryList) ** prevNext,
		int * itemCount, const URI_CHAR * keyFirst, const URI_CHAR * keyAfter,
		const URI_CHAR * valueFirst, const URI_CHAR * valueAfter,
		UriBool plusToSpace, UriBreakConversion breakConversion);



int URI_FUNC(ComposeQueryCharsRequired)(const URI_TYPE(QueryList) * queryList,
		int * charsRequired) {
	const UriBool spaceToPlus = URI_TRUE;
	const UriBool normalizeBreaks = URI_TRUE;

	return URI_FUNC(ComposeQueryCharsRequiredEx)(queryList, charsRequired,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -68,6 +68,10 @@
 
 
 
+#include <limits.h>
+
+
+
 static int URI_FUNC(ComposeQueryEngine)(URI_CHAR * dest,
 		const URI_TYPE(QueryList) * queryList,
 		int maxChars, int * charsWritten, int * charsRequired,
@@ -201,9 +205,15 @@
 		const URI_CHAR * const value = queryList->value;
 		const int worstCase = (normalizeBreaks == URI_TRUE ? 6 : 3);
 		const int keyLen = (key == NULL) ? 0 : (int)URI_STRLEN(key);
-		const int keyRequiredChars = worstCase * keyLen;
+		int keyRequiredChars;
 		const int valueLen = (value == NULL) ? 0 : (int)URI_STRLEN(value);
-		const int valueRequiredChars = worstCase * valueLen;
+		int valueRequiredChars;
+
+		if ((keyLen >= INT_MAX / worstCase) || (valueLen >= INT_MAX / worstCase)) {
+			return URI_ERROR_OUTPUT_TOO_LARGE;
+		}
+		keyRequiredChars = worstCase * keyLen;
+		valueRequiredChars = worstCase * valueLen;
 
 		if (dest == NULL) {
 			(*charsRequired) += ampersandLen + keyRequiredChars + ((value == NULL)
```
