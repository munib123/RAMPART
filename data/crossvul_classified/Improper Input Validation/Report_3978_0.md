# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 3978_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3978_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 1-21 of the vulnerable file.

/* $OpenBSD: scp.c,v 1.209 2020/05/01 06:31:42 djm Exp $ */
/*
 * scp - secure remote copy.  This is basically patched BSD rcp which
 * uses ssh to do the data transfer (instead of using rcmd).
 *
 * NOTE: This version should NOT be suid root.  (This uses ssh to
 * do the transfer and ssh has the necessary privileges.)
 *
 * 1995 Timo Rinne <tri@iki.fi>, Tatu Ylonen <ylo@cs.hut.fi>
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */
/*
 * Copyright (c) 1999 Theo de Raadt.  All rights reserved.
 * Copyright (c) 1999 Aaron Campbell.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,4 +1,4 @@
-/* $OpenBSD: scp.c,v 1.209 2020/05/01 06:31:42 djm Exp $ */
+/* $OpenBSD: scp.c,v 1.210 2020/05/06 20:57:38 djm Exp $ */
 /*
  * scp - secure remote copy.  This is basically patched BSD rcp which
  * uses ssh to do the data transfer (instead of using rcmd).
@@ -1427,9 +1427,7 @@
 			sink(1, vect, src);
 			if (setimes) {
 				setimes = 0;
-				if (utimes(vect[0], tv) == -1)
-					run_err("%s: set times: %s",
-					    vect[0], strerror(errno));
+				(void) utimes(vect[0], tv);
 			}
 			if (mod_flag)
 				(void) chmod(vect[0], mode);
```
