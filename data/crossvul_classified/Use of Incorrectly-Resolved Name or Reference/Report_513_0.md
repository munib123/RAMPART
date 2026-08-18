# CrossVul Fix Pair: Use of Incorrectly-Resolved Name or Reference in c
**Pair ID:** 513_0
**Vulnerability Class:** Use of Incorrectly-Resolved Name or Reference
**CWE:** CWE-706
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `513_0`)

## Vulnerability Information & PoC

## Description
Use of Incorrectly-Resolved Name or Reference - The product uses a name or reference to access a resource, but the name/reference resolves to a resource that is outside of the intended control sphere.

## Vulnerable Code
```c
Lines 1-21 of the vulnerable file.

/* $OpenBSD: scp.c,v 1.197 2018/06/01 04:31:48 dtucker Exp $ */
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
-/* $OpenBSD: scp.c,v 1.197 2018/06/01 04:31:48 dtucker Exp $ */
+/* $OpenBSD: scp.c,v 1.198 2018/11/16 03:03:10 djm Exp $ */
 /*
  * scp - secure remote copy.  This is basically patched BSD rcp which
  * uses ssh to do the data transfer (instead of using rcmd).
@@ -1106,7 +1106,8 @@
 			SCREWUP("size out of range");
 		size = (off_t)ull;
 
-		if ((strchr(cp, '/') != NULL) || (strcmp(cp, "..") == 0)) {
+		if (*cp == '\0' || strchr(cp, '/') != NULL ||
+		    strcmp(cp, ".") == 0 || strcmp(cp, "..") == 0) {
 			run_err("error: unexpected filename: %s", cp);
 			exit(1);
 		}
```
