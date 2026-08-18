# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 2020_6
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2020_6`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 1-31 of the vulnerable file.

/*
 * in/out function for ltree and lquery
 * Teodor Sigaev <teodor@stack.net>
 * contrib/ltree/ltree_io.c
 */
#include "postgres.h"

#include <ctype.h>

#include "ltree.h"
#include "crc32.h"

PG_FUNCTION_INFO_V1(ltree_in);
Datum		ltree_in(PG_FUNCTION_ARGS);

PG_FUNCTION_INFO_V1(ltree_out);
Datum		ltree_out(PG_FUNCTION_ARGS);

PG_FUNCTION_INFO_V1(lquery_in);
Datum		lquery_in(PG_FUNCTION_ARGS);

PG_FUNCTION_INFO_V1(lquery_out);
Datum		lquery_out(PG_FUNCTION_ARGS);


#define UNCHAR ereport(ERROR, \
					   (errcode(ERRCODE_SYNTAX_ERROR), \
						errmsg("syntax error at position %d", \
						pos)));


```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -8,6 +8,7 @@
 #include <ctype.h>
 
 #include "ltree.h"
+#include "utils/memutils.h"
 #include "crc32.h"
 
 PG_FUNCTION_INFO_V1(ltree_in);
@@ -64,6 +65,11 @@
 		ptr += charlen;
 	}
 
+	if (num + 1 > MaxAllocSize / sizeof(nodeitem))
+		ereport(ERROR,
+				(errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED),
+			 errmsg("number of levels (%d) exceeds the maximum allowed (%d)",
+					num + 1, (int) (MaxAllocSize / sizeof(nodeitem)))));
 	list = lptr = (nodeitem *) palloc(sizeof(nodeitem) * (num + 1));
 	ptr = buf;
 	while (*ptr)
@@ -228,6 +234,11 @@
 	}
 
 	num++;
+	if (num > MaxAllocSize / ITEMSIZE)
+		ereport(ERROR,
+				(errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED),
+			 errmsg("number of levels (%d) exceeds the maximum allowed (%d)",
+					num, (int) (MaxAllocSize / ITEMSIZE))));
 	curqlevel = tmpql = (lquery_level *) palloc0(ITEMSIZE * num);
 	ptr = buf;
 	while (*ptr)
```
