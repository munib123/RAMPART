# CrossVul Fix Pair: Authorization Bypass Through User-Controlled Key in c
**Pair ID:** 4237_0
**Vulnerability Class:** Insecure Direct Object Reference (IDOR)
**CWE:** CWE-639
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4237_0`)

## Vulnerability Information & PoC

## Description
Authorization Bypass Through User-Controlled Key - Retrieval of a user record occurs in the system based on some key value that is under user control.

## Vulnerable Code
```c
Lines 1-21 of the vulnerable file.

/*	$OpenBSD: ca.c,v 1.64 2020/07/15 14:45:15 tobhe Exp $	*/

/*
 * Copyright (c) 2010-2013 Reyk Floeter <reyk@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/wait.h>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,4 +1,4 @@
-/*	$OpenBSD: ca.c,v 1.64 2020/07/15 14:45:15 tobhe Exp $	*/
+/*	$OpenBSD: ca.c,v 1.65 2020/07/27 14:22:53 tobhe Exp $	*/
 
 /*
  * Copyright (c) 2010-2013 Reyk Floeter <reyk@openbsd.org>
@@ -1420,7 +1420,7 @@
 	if (localkey == NULL)
 		goto sslerr;
 
-	if (peerkey && !EVP_PKEY_cmp(peerkey, localkey)) {
+	if (peerkey && EVP_PKEY_cmp(peerkey, localkey) != 1) {
 		log_debug("%s: public key does not match %s", __func__, file);
 		goto done;
 	}
```
