# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 2375_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2375_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 8-48 of the vulnerable file.

/* This header contains the private mechglue definitions. */

#ifndef _GSS_MECHGLUEP_H
#define _GSS_MECHGLUEP_H

#include "autoconf.h"
#include "mechglue.h"
#include "gssapiP_generic.h"

#define	g_OID_copy(o1, o2)					\
do {								\
	memcpy((o1)->elements, (o2)->elements, (o2)->length);	\
	(o1)->length = (o2)->length;				\
} while (0)

/*
 * Array of context IDs typed by mechanism OID
 */
typedef struct gss_union_ctx_id_struct {
	struct gss_union_ctx_id_struct *loopback;
	struct gss_union_ctx_id_struct *interposer;
	gss_OID			mech_type;
	gss_ctx_id_t		internal_ctx_id;
} gss_union_ctx_id_desc, *gss_union_ctx_id_t;

/*
 * Generic GSSAPI names.  A name can either be a generic name, or a
 * mechanism specific name....
 */
typedef struct gss_name_struct {
	struct gss_name_struct *loopback;
	gss_OID			name_type;
	gss_buffer_t		external_name;
	/*
	 * These last two fields are only filled in for mechanism
	 * names.
	 */
	gss_OID			mech_type;
	gss_name_t		mech_name;
} gss_union_name_desc, *gss_union_name_t;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -25,7 +25,6 @@
  */
 typedef struct gss_union_ctx_id_struct {
 	struct gss_union_ctx_id_struct *loopback;
-	struct gss_union_ctx_id_struct *interposer;
 	gss_OID			mech_type;
 	gss_ctx_id_t		internal_ctx_id;
 } gss_union_ctx_id_desc, *gss_union_ctx_id_t;
```
