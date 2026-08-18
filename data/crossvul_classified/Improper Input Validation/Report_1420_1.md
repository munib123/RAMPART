# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 1420_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1420_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 1-21 of the vulnerable file.

/*	$OpenBSD: tcp_input.c,v 1.359 2018/09/17 14:07:48 friehm Exp $	*/
/*	$NetBSD: tcp_input.c,v 1.23 1996/02/13 23:43:44 christos Exp $	*/

/*
 * Copyright (c) 1982, 1986, 1988, 1990, 1993, 1994
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,4 +1,4 @@
-/*	$OpenBSD: tcp_input.c,v 1.359 2018/09/17 14:07:48 friehm Exp $	*/
+/*	$OpenBSD: tcp_input.c,v 1.360 2019/07/10 18:45:31 bluhm Exp $	*/
 /*	$NetBSD: tcp_input.c,v 1.23 1996/02/13 23:43:44 christos Exp $	*/
 
 /*
@@ -2492,6 +2492,8 @@
 				 * ACKs some data in middle of a hole; need to
 				 * split current hole
 				 */
+				if (tp->snd_numholes >= TCP_SACKHOLE_LIMIT)
+					goto done;
 				temp = (struct sackhole *)
 				    pool_get(&sackhl_pool, PR_NOWAIT);
 				if (temp == NULL)
@@ -2519,6 +2521,8 @@
 			 * Need to append new hole at end.
 			 * Last hole is p (and it's not NULL).
 			 */
+			if (tp->snd_numholes >= TCP_SACKHOLE_LIMIT)
+				goto done;
 			temp = (struct sackhole *)
 			    pool_get(&sackhl_pool, PR_NOWAIT);
 			if (temp == NULL)
```
