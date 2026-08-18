# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 5007_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5007_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1-21 of the vulnerable file.

/* $Id: minissdpd.c,v 1.50 2015/08/06 14:05:49 nanard Exp $ */
/* vim: tabstop=4 shiftwidth=4 noexpandtab
 * MiniUPnP project
 * (c) 2007-2016 Thomas Bernard
 * website : http://miniupnp.free.fr/ or http://miniupnp.tuxfamily.org/
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,4 +1,4 @@
-/* $Id: minissdpd.c,v 1.50 2015/08/06 14:05:49 nanard Exp $ */
+/* $Id: minissdpd.c,v 1.53 2016/03/01 18:06:46 nanard Exp $ */
 /* vim: tabstop=4 shiftwidth=4 noexpandtab
  * MiniUPnP project
  * (c) 2007-2016 Thomas Bernard
@@ -847,7 +847,7 @@
 	type = buf[0];
 	p = buf + 1;
 	DECODELENGTH_CHECKLIMIT(l, p, buf + n);
-	if(p+l > buf+n) {
+	if(l > (unsigned)(buf+n-p)) {
 		syslog(LOG_WARNING, "bad request (length encoding l=%u n=%u)",
 		       l, (unsigned)n);
 		goto error;
@@ -969,7 +969,7 @@
 			goto error;
 		}
 		DECODELENGTH_CHECKLIMIT(l, p, buf + n);
-		if(p+l > buf+n) {
+		if(l > (unsigned)(buf+n-p)) {
 			syslog(LOG_WARNING, "bad request (length encoding)");
 			goto error;
 		}
@@ -987,7 +987,7 @@
 		newserv->usn[l] = '\0';
 		p += l;
 		DECODELENGTH_CHECKLIMIT(l, p, buf + n);
-		if(p+l > buf+n) {
+		if(l > (unsigned)(buf+n-p)) {
 			syslog(LOG_WARNING, "bad request (length encoding)");
 			goto error;
 		}
@@ -1005,7 +1005,7 @@
 		newserv->server[l] = '\0';
 		p += l;
 		DECODELENGTH_CHECKLIMIT(l, p, buf + n);
-		if(p+l > buf+n) {
+		if(l > (unsigned)(buf+n-p)) {
 			syslog(LOG_WARNING, "bad request (length encoding)");
 			goto error;
 		}
```
