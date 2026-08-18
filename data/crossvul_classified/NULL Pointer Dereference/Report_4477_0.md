# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 4477_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4477_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 1-21 of the vulnerable file.

/*	$OpenBSD: lka_filter.c,v 1.64 2020/12/20 13:27:46 martijn Exp $	*/

/*
 * Copyright (c) 2018 Gilles Chehade <gilles@poolp.org>
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
#include <sys/queue.h>
#include <sys/tree.h>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,4 +1,4 @@
-/*	$OpenBSD: lka_filter.c,v 1.64 2020/12/20 13:27:46 martijn Exp $	*/
+/*	$OpenBSD: lka_filter.c,v 1.65 2020/12/23 20:17:49 millert Exp $	*/
 
 /*
  * Copyright (c) 2018 Gilles Chehade <gilles@poolp.org>
@@ -600,11 +600,6 @@
 		filter_data(fs->id, line);
 
 		goto nextline;
-
-	case IO_DISCONNECTED:
-		io_free(fs->io);
-		fs->io = NULL;
-		break;
 	}
 }
 
```
