# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 2020_1
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2020_1`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 1-36 of the vulnerable file.

/*
 * contrib/hstore/hstore_io.c
 */
#include "postgres.h"

#include <ctype.h>

#include "access/htup_details.h"
#include "catalog/pg_type.h"
#include "funcapi.h"
#include "lib/stringinfo.h"
#include "libpq/pqformat.h"
#include "utils/builtins.h"
#include "utils/json.h"
#include "utils/lsyscache.h"
#include "utils/typcache.h"

#include "hstore.h"

PG_MODULE_MAGIC;

/* old names for C functions */
HSTORE_POLLUTE(hstore_from_text, tconvert);


typedef struct
{
	char	   *begin;
	char	   *ptr;
	char	   *cur;
	char	   *word;
	int			wordlen;

	Pairs	   *pairs;
	int			pcur;
	int			plen;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -13,6 +13,7 @@
 #include "utils/builtins.h"
 #include "utils/json.h"
 #include "utils/lsyscache.h"
+#include "utils/memutils.h"
 #include "utils/typcache.h"
 
 #include "hstore.h"
@@ -439,6 +440,11 @@
 		PG_RETURN_POINTER(out);
 	}
 
+	if (pcount < 0 || pcount > MaxAllocSize / sizeof(Pairs))
+		ereport(ERROR,
+				(errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED),
+			  errmsg("number of pairs (%d) exceeds the maximum allowed (%d)",
+					 pcount, (int) (MaxAllocSize / sizeof(Pairs)))));
 	pairs = palloc(pcount * sizeof(Pairs));
 
 	for (i = 0; i < pcount; ++i)
@@ -554,6 +560,13 @@
 					  TEXTOID, -1, false, 'i',
 					  &key_datums, &key_nulls, &key_count);
 
+	/* see discussion in hstoreArrayToPairs() */
+	if (key_count > MaxAllocSize / sizeof(Pairs))
+		ereport(ERROR,
+				(errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED),
+			  errmsg("number of pairs (%d) exceeds the maximum allowed (%d)",
+					 key_count, (int) (MaxAllocSize / sizeof(Pairs)))));
+
 	/* value_array might be NULL */
 
 	if (PG_ARGISNULL(1))
@@ -675,6 +688,13 @@
 					  &in_datums, &in_nulls, &in_count);
 
 	count = in_count / 2;
+
+	/* see discussion in hstoreArrayToPairs() */
+	if (count > MaxAllocSize / sizeof(Pairs))
+		ereport(ERROR,
+				(errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED),
+			  errmsg("number of pairs (%d) exceeds the maximum allowed (%d)",
+					 count, (int) (MaxAllocSize / sizeof(Pairs)))));
 
 	pairs = palloc(count * sizeof(Pairs));
 
@@ -807,6 +827,7 @@
 		my_extra->ncolumns = ncolumns;
 	}
 
+	Assert(ncolumns <= MaxTupleAttributeNumber);		/* thus, no overflow */
 	pairs = palloc(ncolumns * sizeof(Pairs));
 
 	if (rec)
```
