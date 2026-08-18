# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 295_2
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `295_2`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 1-21 of the vulnerable file.

/* $OpenBSD: auth2-pubkey.c,v 1.82 2018/07/11 18:55:11 markus Exp $ */
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
-/* $OpenBSD: auth2-pubkey.c,v 1.82 2018/07/11 18:55:11 markus Exp $ */
+/* $OpenBSD: auth2-pubkey.c,v 1.83 2018/07/31 03:10:27 djm Exp $ */
 /*
  * Copyright (c) 2000 Markus Friedl.  All rights reserved.
  *
@@ -86,19 +86,15 @@
 {
 	Authctxt *authctxt = ssh->authctxt;
 	struct passwd *pw = authctxt->pw;
-	struct sshbuf *b;
+	struct sshbuf *b = NULL;
 	struct sshkey *key = NULL;
-	char *pkalg, *userstyle = NULL, *key_s = NULL, *ca_s = NULL;
-	u_char *pkblob, *sig, have_sig;
+	char *pkalg = NULL, *userstyle = NULL, *key_s = NULL, *ca_s = NULL;
+	u_char *pkblob = NULL, *sig = NULL, have_sig;
 	size_t blen, slen;
 	int r, pktype;
 	int authenticated = 0;
 	struct sshauthopt *authopts = NULL;
 
-	if (!authctxt->valid) {
-		debug2("%s: disabled because of invalid user", __func__);
-		return 0;
-	}
 	if ((r = sshpkt_get_u8(ssh, &have_sig)) != 0 ||
 	    (r = sshpkt_get_cstring(ssh, &pkalg, NULL)) != 0 ||
 	    (r = sshpkt_get_string(ssh, &pkblob, &blen)) != 0)
@@ -164,6 +160,11 @@
 				fatal("%s: sshbuf_put_string session id: %s",
 				    __func__, ssh_err(r));
 		}
+		if (!authctxt->valid || authctxt->user == NULL) {
+			debug2("%s: disabled because of invalid user",
+			    __func__);
+			goto done;
+		}
 		/* reconstruct packet */
 		xasprintf(&userstyle, "%s%s%s", authctxt->user,
 		    authctxt->style ? ":" : "",
@@ -180,7 +181,6 @@
 #ifdef DEBUG_PK
 		sshbuf_dump(b, stderr);
 #endif
-
 		/* test for correct signature */
 		authenticated = 0;
 		if (PRIVSEP(user_key_allowed(ssh, pw, key, 1, &authopts)) &&
@@ -191,7 +191,6 @@
 			authenticated = 1;
 		}
 		sshbuf_free(b);
-		free(sig);
 		auth2_record_key(authctxt, authenticated, key);
 	} else {
 		debug("%s: test pkalg %s pkblob %s%s%s",
@@ -202,6 +201,11 @@
 		if ((r = sshpkt_get_end(ssh)) != 0)
 			fatal("%s: %s", __func__, ssh_err(r));
 
+		if (!authctxt->valid || authctxt->user == NULL) {
+			debug2("%s: disabled because of invalid user",
+			    __func__);
+			goto done;
+		}
 		/* XXX fake reply and always send PK_OK ? */
 		/*
 		 * XXX this allows testing whether a user is allowed
@@ -235,6 +239,7 @@
 	free(pkblob);
 	free(key_s);
 	free(ca_s);
+	free(sig);
 	return authenticated;
 }
 
```
