# CrossVul Fix Pair: Unchecked Return Value in c
**Pair ID:** 4604_0
**Vulnerability Class:** Unchecked Return Value
**CWE:** CWE-252
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4604_0`)

## Vulnerability Information & PoC

## Description
Unchecked Return Value - Two common programmer assumptions are this function call can never fail and it doesn't matter if this function call fails.

## Vulnerable Code
```c
Lines 1-21 of the vulnerable file.

/*	$OpenBSD: smtp_session.c,v 1.421 2020/01/08 00:05:38 gilles Exp $	*/

/*
 * Copyright (c) 2008 Gilles Chehade <gilles@poolp.org>
 * Copyright (c) 2008 Pierre-Yves Ritschard <pyr@openbsd.org>
 * Copyright (c) 2008-2009 Jacek Masiulaniec <jacekm@dobremiasto.net>
 * Copyright (c) 2012 Eric Faurot <eric@openbsd.org>
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

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,4 +1,4 @@
-/*	$OpenBSD: smtp_session.c,v 1.421 2020/01/08 00:05:38 gilles Exp $	*/
+/*	$OpenBSD: smtp_session.c,v 1.422 2020/01/28 21:35:00 gilles Exp $	*/
 
 /*
  * Copyright (c) 2008 Gilles Chehade <gilles@poolp.org>
@@ -2236,24 +2236,22 @@
 		memmove(maddr->user, p, strlen(p) + 1);
 	}
 
-	if (!valid_localpart(maddr->user) ||
-	    !valid_domainpart(maddr->domain)) {
-		/* accept empty return-path in MAIL FROM, required for bounces */
-		if (mailfrom && maddr->user[0] == '\0' && maddr->domain[0] == '\0')
-			return (1);
-
-		/* no user-part, reject */
-		if (maddr->user[0] == '\0')
-			return (0);
-
-		/* no domain, local user */
-		if (maddr->domain[0] == '\0') {
-			(void)strlcpy(maddr->domain, domain,
-			    sizeof(maddr->domain));
-			return (1);
-		}
+	/* accept empty return-path in MAIL FROM, required for bounces */
+	if (mailfrom && maddr->user[0] == '\0' && maddr->domain[0] == '\0')
+		return (1);
+
+	/* no or invalid user-part, reject */
+	if (maddr->user[0] == '\0' || !valid_localpart(maddr->user))
 		return (0);
-	}
+
+	/* no domain part, local user */
+	if (maddr->domain[0] == '\0') {
+		(void)strlcpy(maddr->domain, domain,
+			sizeof(maddr->domain));
+	}
+
+	if (!valid_domainpart(maddr->domain))
+		return (0);
 
 	return (1);
 }
```
