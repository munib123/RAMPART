# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 1709_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1709_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1-21 of the vulnerable file.

/* $Id: igd_desc_parse.c,v 1.16 2014/11/17 17:19:13 nanard Exp $ */
/* Project : miniupnp
 * http://miniupnp.free.fr/
 * Author : Thomas Bernard
 * Copyright (c) 2005-2014 Thomas Bernard
 * This software is subject to the conditions detailed in the
 * LICENCE file provided in this distribution. */

#include "igd_desc_parse.h"
#include <stdio.h>
#include <string.h>

/* Start element handler :
 * update nesting level counter and copy element name */
void IGDstartelt(void * d, const char * name, int l)
{
	struct IGDdatas * datas = (struct IGDdatas *)d;
	memcpy( datas->cureltname, name, l);
	datas->cureltname[l] = '\0';
	datas->level++;
	if( (l==7) && !memcmp(name, "service", l) ) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,8 +1,8 @@
-/* $Id: igd_desc_parse.c,v 1.16 2014/11/17 17:19:13 nanard Exp $ */
+/* $Id: igd_desc_parse.c,v 1.17 2015/09/15 13:30:04 nanard Exp $ */
 /* Project : miniupnp
  * http://miniupnp.free.fr/
  * Author : Thomas Bernard
- * Copyright (c) 2005-2014 Thomas Bernard
+ * Copyright (c) 2005-2015 Thomas Bernard
  * This software is subject to the conditions detailed in the
  * LICENCE file provided in this distribution. */
 
@@ -15,7 +15,9 @@
 void IGDstartelt(void * d, const char * name, int l)
 {
 	struct IGDdatas * datas = (struct IGDdatas *)d;
-	memcpy( datas->cureltname, name, l);
+	if(l >= MINIUPNPC_URL_MAXSIZE)
+		l = MINIUPNPC_URL_MAXSIZE-1;
+	memcpy(datas->cureltname, name, l);
 	datas->cureltname[l] = '\0';
 	datas->level++;
 	if( (l==7) && !memcmp(name, "service", l) ) {
```
