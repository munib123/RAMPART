# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 445_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `445_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 58-98 of the vulnerable file.

#  include <uriparser/UriDefsUnicode.h>
#  include <wchar.h>
# endif



#ifndef URI_DOXYGEN
# include <uriparser/Uri.h>
# include "UriCommon.h"
#endif



/*extern*/ const URI_CHAR * const URI_FUNC(SafeToPointTo) = _UT("X");
/*extern*/ const URI_CHAR * const URI_FUNC(ConstPwd) = _UT(".");
/*extern*/ const URI_CHAR * const URI_FUNC(ConstParent) = _UT("..");



void URI_FUNC(ResetUri)(URI_TYPE(Uri) * uri) {
	memset(uri, 0, sizeof(URI_TYPE(Uri)));
}



/* Compares two text ranges for equal text content */
int URI_FUNC(CompareRange)(
		const URI_TYPE(TextRange) * a,
		const URI_TYPE(TextRange) * b) {
	int diff;

	/* NOTE: Both NULL means equal! */
	if ((a == NULL) || (b == NULL)) {
		return ((a == NULL) ? 0 : 1) - ((b == NULL) ? 0 : 1);
	}

	/* NOTE: Both NULL means equal! */
	if ((a->first == NULL) || (b->first == NULL)) {
		return ((a->first == NULL) ? 0 : 1) - ((b->first == NULL) ? 0 : 1);
	}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -75,6 +75,9 @@
 
 
 void URI_FUNC(ResetUri)(URI_TYPE(Uri) * uri) {
+	if (uri == NULL) {
+		return;
+	}
 	memset(uri, 0, sizeof(URI_TYPE(Uri)));
 }
 
```
