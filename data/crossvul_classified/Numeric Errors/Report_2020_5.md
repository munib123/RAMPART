# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 2020_5
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2020_5`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 1-28 of the vulnerable file.

/* contrib/ltree/ltree.h */

#ifndef __LTREE_H__
#define __LTREE_H__

#include "fmgr.h"
#include "tsearch/ts_locale.h"

typedef struct
{
	uint16		len;
	char		name[1];
} ltree_level;

#define LEVEL_HDRSIZE	(offsetof(ltree_level,name))
#define LEVEL_NEXT(x)	( (ltree_level*)( ((char*)(x)) + MAXALIGN(((ltree_level*)(x))->len + LEVEL_HDRSIZE) ) )

typedef struct
{
	int32		vl_len_;		/* varlena header (do not touch directly!) */
	uint16		numlevel;
	char		data[1];
} ltree;

#define LTREE_HDRSIZE	MAXALIGN( offsetof(ltree, data) )
#define LTREE_FIRST(x)	( (ltree_level*)( ((char*)(x))+LTREE_HDRSIZE ) )


```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5,6 +5,7 @@
 
 #include "fmgr.h"
 #include "tsearch/ts_locale.h"
+#include "utils/memutils.h"
 
 typedef struct
 {
@@ -111,6 +112,8 @@
 
 #define HDRSIZEQT		MAXALIGN(VARHDRSZ + sizeof(int32))
 #define COMPUTESIZE(size,lenofoperand)	( HDRSIZEQT + (size) * sizeof(ITEM) + (lenofoperand) )
+#define LTXTQUERY_TOO_BIG(size,lenofoperand) \
+	((size) > (MaxAllocSize - HDRSIZEQT - (lenofoperand)) / sizeof(ITEM))
 #define GETQUERY(x)  (ITEM*)( (char*)(x)+HDRSIZEQT )
 #define GETOPERAND(x)	( (char*)GETQUERY(x) + ((ltxtquery*)x)->size * sizeof(ITEM) )
 
```
