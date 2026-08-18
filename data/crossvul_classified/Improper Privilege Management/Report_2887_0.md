# CrossVul Fix Pair: Improper Privilege Management in c
**Pair ID:** 2887_0
**Vulnerability Class:** Improper Privilege Management
**CWE:** CWE-269
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2887_0`)

## Vulnerability Information & PoC

## Description
Improper Privilege Management - The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Vulnerable Code
```c
Lines 1-21 of the vulnerable file.

/* $OpenBSD: sftp-server.c,v 1.110 2016/09/12 01:22:38 deraadt Exp $ */
/*
 * Copyright (c) 2000-2004 Markus Friedl.  All rights reserved.
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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/mount.h>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,4 +1,4 @@
-/* $OpenBSD: sftp-server.c,v 1.110 2016/09/12 01:22:38 deraadt Exp $ */
+/* $OpenBSD: sftp-server.c,v 1.111 2017/04/04 00:24:56 djm Exp $ */
 /*
  * Copyright (c) 2000-2004 Markus Friedl.  All rights reserved.
  *
@@ -683,8 +683,8 @@
 	logit("open \"%s\" flags %s mode 0%o",
 	    name, string_from_portable(pflags), mode);
 	if (readonly &&
-	    ((flags & O_ACCMODE) == O_WRONLY ||
-	    (flags & O_ACCMODE) == O_RDWR)) {
+	    ((flags & O_ACCMODE) != O_RDONLY ||
+	    (flags & (O_CREAT|O_TRUNC)) != 0)) {
 		verbose("Refusing open request in read-only mode");
 		status = SSH2_FX_PERMISSION_DENIED;
 	} else {
```
