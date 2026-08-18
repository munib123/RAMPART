# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 2020_7
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2020_7`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 1-32 of the vulnerable file.

/*
 * txtquery io
 * Teodor Sigaev <teodor@stack.net>
 * contrib/ltree/ltxtquery_io.c
 */
#include "postgres.h"

#include <ctype.h>

#include "crc32.h"
#include "ltree.h"

PG_FUNCTION_INFO_V1(ltxtq_in);
Datum		ltxtq_in(PG_FUNCTION_ARGS);

PG_FUNCTION_INFO_V1(ltxtq_out);
Datum		ltxtq_out(PG_FUNCTION_ARGS);


/* parser's states */
#define WAITOPERAND 1
#define INOPERAND 2
#define WAITOPERATOR	3

/*
 * node of query tree, also used
 * for storing polish notation in parser
 */
typedef struct NODE
{
	int32		type;
	int32		val;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -9,6 +9,7 @@
 
 #include "crc32.h"
 #include "ltree.h"
+#include "miscadmin.h"
 
 PG_FUNCTION_INFO_V1(ltxtq_in);
 Datum		ltxtq_in(PG_FUNCTION_ARGS);
@@ -212,6 +213,9 @@
 	int32		lenstack = 0;
 	uint16		flag = 0;
 
+	/* since this function recurses, it could be driven to stack overflow */
+	check_stack_depth();
+
 	while ((type = gettoken_query(state, &val, &lenval, &strval, &flag)) != END)
 	{
 		switch (type)
@@ -276,6 +280,9 @@
 static void
 findoprnd(ITEM *ptr, int32 *pos)
 {
+	/* since this function recurses, it could be driven to stack overflow. */
+	check_stack_depth();
+
 	if (ptr[*pos].type == VAL || ptr[*pos].type == VALTRUE)
 	{
 		ptr[*pos].left = 0;
@@ -340,8 +347,12 @@
 				 errmsg("syntax error"),
 				 errdetail("Empty query.")));
 
-	/* make finish struct */
+	if (LTXTQUERY_TOO_BIG(state.num, state.sumlen))
+		ereport(ERROR,
+				(errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED),
+				 errmsg("ltxtquery is too large")));
 	commonlen = COMPUTESIZE(state.num, state.sumlen);
+
 	query = (ltxtquery *) palloc(commonlen);
 	SET_VARSIZE(query, commonlen);
 	query->size = state.num;
```
