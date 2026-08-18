# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 2020_2
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2020_2`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 1-31 of the vulnerable file.

/*
 * contrib/hstore/hstore_op.c
 */
#include "postgres.h"

#include "access/hash.h"
#include "access/htup_details.h"
#include "catalog/pg_type.h"
#include "funcapi.h"
#include "utils/builtins.h"

#include "hstore.h"

/* old names for C functions */
HSTORE_POLLUTE(hstore_fetchval, fetchval);
HSTORE_POLLUTE(hstore_exists, exists);
HSTORE_POLLUTE(hstore_defined, defined);
HSTORE_POLLUTE(hstore_delete, delete);
HSTORE_POLLUTE(hstore_concat, hs_concat);
HSTORE_POLLUTE(hstore_contains, hs_contains);
HSTORE_POLLUTE(hstore_contained, hs_contained);
HSTORE_POLLUTE(hstore_akeys, akeys);
HSTORE_POLLUTE(hstore_avals, avals);
HSTORE_POLLUTE(hstore_skeys, skeys);
HSTORE_POLLUTE(hstore_svals, svals);
HSTORE_POLLUTE(hstore_each, each);


/*
 * We're often finding a sequence of keys in ascending order. The
 * "lowbound" parameter is used to cache lower bounds of searches
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -8,6 +8,7 @@
 #include "catalog/pg_type.h"
 #include "funcapi.h"
 #include "utils/builtins.h"
+#include "utils/memutils.h"
 
 #include "hstore.h"
 
@@ -89,6 +90,19 @@
 		*npairs = 0;
 		return NULL;
 	}
+
+	/*
+	 * A text array uses at least eight bytes per element, so any overflow in
+	 * "key_count * sizeof(Pairs)" is small enough for palloc() to catch.
+	 * However, credible improvements to the array format could invalidate
+	 * that assumption.  Therefore, use an explicit check rather than relying
+	 * on palloc() to complain.
+	 */
+	if (key_count > MaxAllocSize / sizeof(Pairs))
+		ereport(ERROR,
+				(errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED),
+			  errmsg("number of pairs (%d) exceeds the maximum allowed (%d)",
+					 key_count, (int) (MaxAllocSize / sizeof(Pairs)))));
 
 	key_pairs = palloc(sizeof(Pairs) * key_count);
 
@@ -648,6 +662,7 @@
 		PG_RETURN_POINTER(out);
 	}
 
+	/* hstoreArrayToPairs() checked overflow */
 	out_pairs = palloc(sizeof(Pairs) * nkeys);
 	bufsiz = 0;
 
```
