# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 295_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `295_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 1-21 of the vulnerable file.

/* $OpenBSD: auth2-gss.c,v 1.28 2018/07/10 09:13:30 djm Exp $ */

/*
 * Copyright (c) 2001-2003 Simon Wilkinson. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,4 +1,4 @@
-/* $OpenBSD: auth2-gss.c,v 1.28 2018/07/10 09:13:30 djm Exp $ */
+/* $OpenBSD: auth2-gss.c,v 1.29 2018/07/31 03:10:27 djm Exp $ */
 
 /*
  * Copyright (c) 2001-2003 Simon Wilkinson. All rights reserved.
@@ -65,9 +65,6 @@
 	size_t len;
 	u_char *doid = NULL;
 
-	if (!authctxt->valid || authctxt->user == NULL)
-		return (0);
-
 	if ((r = sshpkt_get_u32(ssh, &mechs)) != 0)
 		fatal("%s: %s", __func__, ssh_err(r));
 
@@ -98,6 +95,12 @@
 	if (!present) {
 		free(doid);
 		authctxt->server_caused_failure = 1;
+		return (0);
+	}
+
+	if (!authctxt->valid || authctxt->user == NULL) {
+		debug2("%s: disabled because of invalid user", __func__);
+		free(doid);
 		return (0);
 	}
 
```
