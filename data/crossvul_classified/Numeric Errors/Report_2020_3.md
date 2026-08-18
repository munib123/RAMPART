# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 2020_3
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2020_3`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 1-28 of the vulnerable file.

/*
 * contrib/intarray/_int.h
 */
#ifndef ___INT_H__
#define ___INT_H__

#include "utils/array.h"

/* number ranges for compression */
#define MAXNUMRANGE 100

/* useful macros for accessing int4 arrays */
#define ARRPTR(x)  ( (int32 *) ARR_DATA_PTR(x) )
#define ARRNELEMS(x)  ArrayGetNItems(ARR_NDIM(x), ARR_DIMS(x))

/* reject arrays we can't handle; to wit, those containing nulls */
#define CHECKARRVALID(x) \
	do { \
		if (ARR_HASNULL(x) && array_contains_nulls(x)) \
			ereport(ERROR, \
					(errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED), \
					 errmsg("array must not contain nulls"))); \
	} while(0)

#define ARRISEMPTY(x)  (ARRNELEMS(x) == 0)

/* sort the elements of the array */
#define SORT(x) \
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5,6 +5,7 @@
 #define ___INT_H__
 
 #include "utils/array.h"
+#include "utils/memutils.h"
 
 /* number ranges for compression */
 #define MAXNUMRANGE 100
@@ -137,6 +138,7 @@
 
 #define HDRSIZEQT	offsetof(QUERYTYPE, items)
 #define COMPUTESIZE(size)	( HDRSIZEQT + (size) * sizeof(ITEM) )
+#define QUERYTYPEMAXITEMS	((MaxAllocSize - HDRSIZEQT) / sizeof(ITEM))
 #define GETQUERY(x)  ( (x)->items )
 
 /* "type" codes for ITEM */
```
