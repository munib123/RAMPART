# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2540_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2540_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1-22 of the vulnerable file.

/* $Id: upnpreplyparse.c,v 1.19 2015/07/15 10:29:11 nanard Exp $ */
/* MiniUPnP project
 * http://miniupnp.free.fr/ or http://miniupnp.tuxfamily.org/
 * (c) 2006-2015 Thomas Bernard
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "upnpreplyparse.h"
#include "minixml.h"

static void
NameValueParserStartElt(void * d, const char * name, int l)
{
	struct NameValueParserData * data = (struct NameValueParserData *)d;
	data->topelt = 1;
    if(l>63)
        l = 63;
    memcpy(data->curelt, name, l);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,7 +1,8 @@
 /* $Id: upnpreplyparse.c,v 1.19 2015/07/15 10:29:11 nanard Exp $ */
-/* MiniUPnP project
+/* vim: tabstop=4 shiftwidth=4 noexpandtab
+ * MiniUPnP project
  * http://miniupnp.free.fr/ or http://miniupnp.tuxfamily.org/
- * (c) 2006-2015 Thomas Bernard
+ * (c) 2006-2017 Thomas Bernard
  * This software is subject to the conditions detailed
  * in the LICENCE file provided within the distribution */
 
@@ -104,9 +105,7 @@
                struct NameValueParserData * data)
 {
 	struct xmlparser parser;
-	data->l_head = NULL;
-	data->portListing = NULL;
-	data->portListingLength = 0;
+	memset(data, 0, sizeof(struct NameValueParserData));
 	/* init xmlparser object */
 	parser.xmlstart = buffer;
 	parser.xmlsize = bufsize;
```
