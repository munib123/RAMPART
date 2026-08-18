# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 295_1
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `295_1`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 1-21 of the vulnerable file.

/* $OpenBSD: auth2-hostbased.c,v 1.35 2018/07/09 21:35:50 markus Exp $ */
/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,4 +1,4 @@
-/* $OpenBSD: auth2-hostbased.c,v 1.35 2018/07/09 21:35:50 markus Exp $ */
+/* $OpenBSD: auth2-hostbased.c,v 1.36 2018/07/31 03:10:27 djm Exp $ */
 /*
  * Copyright (c) 2000 Markus Friedl.  All rights reserved.
  *
@@ -66,10 +66,6 @@
 	size_t alen, blen, slen;
 	int r, pktype, authenticated = 0;
 
-	if (!authctxt->valid) {
-		debug2("%s: disabled because of invalid user", __func__);
-		return 0;
-	}
 	/* XXX use sshkey_froms() */
 	if ((r = sshpkt_get_cstring(ssh, &pkalg, &alen)) != 0 ||
 	    (r = sshpkt_get_string(ssh, &pkblob, &blen)) != 0 ||
@@ -113,6 +109,11 @@
 	if (match_pattern_list(pkalg, options.hostbased_key_types, 0) != 1) {
 		logit("%s: key type %s not in HostbasedAcceptedKeyTypes",
 		    __func__, sshkey_type(key));
+		goto done;
+	}
+
+	if (!authctxt->valid || authctxt->user == NULL) {
+		debug2("%s: disabled because of invalid user", __func__);
 		goto done;
 	}
 
```
