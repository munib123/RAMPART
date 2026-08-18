# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5795_4
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5795_4`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1-35 of the vulnerable file.

/*
 * $Id: json_object.h,v 1.12 2006/01/30 23:07:57 mclark Exp $
 *
 * Copyright (c) 2004, 2005 Metaparadigm Pte. Ltd.
 * Michael Clark <michael@metaparadigm.com>
 * Copyright (c) 2009 Hewlett-Packard Development Company, L.P.
 *
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See COPYING for details.
 *
 */

#ifndef _json_object_h_
#define _json_object_h_

#include "json_inttypes.h"

#ifdef __cplusplus
extern "C" {
#endif

#define JSON_OBJECT_DEF_HASH_ENTRIES 16

/**
 * A flag for the json_object_to_json_string_ext() and
 * json_object_to_file_ext() functions which causes the output
 * to have no extra whitespace or formatting applied.
 */
#define JSON_C_TO_STRING_PLAIN      0
/**
 * A flag for the json_object_to_json_string_ext() and
 * json_object_to_file_ext() functions which causes the output to have
 * minimal whitespace inserted to make things slightly more readable.
 */
#define JSON_C_TO_STRING_SPACED     (1<<0)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -12,6 +12,14 @@
 
 #ifndef _json_object_h_
 #define _json_object_h_
+
+#ifdef __GNUC__
+#define THIS_FUNCTION_IS_DEPRECATED(func) func __attribute__ ((deprecated))
+#elif defined(_MSC_VER)
+#define THIS_FUNCTION_IS_DEPRECATED(func) __declspec(deprecated) func
+#else
+#define THIS_FUNCTION_IS_DEPRECATED(func) func
+#endif
 
 #include "json_inttypes.h"
 
@@ -279,8 +287,8 @@
  * @returns the json_object associated with the given field name
  * @deprecated Please use json_object_object_get_ex
  */
-extern struct json_object* json_object_object_get(struct json_object* obj,
-						  const char *key);
+THIS_FUNCTION_IS_DEPRECATED(extern struct json_object* json_object_object_get(struct json_object* obj,
+						  const char *key));
 
 /** Get the json_object associated with a given object field.  
  *
```
