# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 1420_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1420_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 1-21 of the vulnerable file.

/*	$OpenBSD: tcp.h,v 1.20 2013/08/12 21:57:16 bluhm Exp $	*/
/*	$NetBSD: tcp.h,v 1.8 1995/04/17 05:32:58 cgd Exp $	*/

/*
 * Copyright (c) 1982, 1986, 1993
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
-/*	$OpenBSD: tcp.h,v 1.20 2013/08/12 21:57:16 bluhm Exp $	*/
+/*	$OpenBSD: tcp.h,v 1.21 2019/07/10 18:45:31 bluhm Exp $	*/
 /*	$NetBSD: tcp.h,v 1.8 1995/04/17 05:32:58 cgd Exp $	*/
 
 /*
@@ -102,7 +102,8 @@
 #define	TCPOPT_SACK_HDR   (TCPOPT_NOP<<24|TCPOPT_NOP<<16|TCPOPT_SACK<<8)
 /* Miscellaneous constants */
 #define	MAX_SACK_BLKS	6	/* Max # SACK blocks stored at sender side */
-#define	TCP_MAX_SACK	3	/* MAX # SACKs sent in any segment */
+#define	TCP_MAX_SACK	3	/* Max # SACKs sent in any segment */
+#define	TCP_SACKHOLE_LIMIT 128	/* Max # SACK holes per connection */
 
 #define	TCP_MAXBURST	4	/* Max # packets after leaving Fast Rxmit */
 
```
