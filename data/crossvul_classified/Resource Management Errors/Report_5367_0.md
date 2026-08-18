# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 5367_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5367_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 1-21 of the vulnerable file.

/* $OpenBSD: kex.c,v 1.126 2016/09/28 21:44:52 djm Exp $ */
/*
 * Copyright (c) 2000, 2001 Markus Friedl.  All rights reserved.
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
-/* $OpenBSD: kex.c,v 1.126 2016/09/28 21:44:52 djm Exp $ */
+/* $OpenBSD: kex.c,v 1.127 2016/10/10 19:28:48 markus Exp $ */
 /*
  * Copyright (c) 2000, 2001 Markus Friedl.  All rights reserved.
  *
@@ -481,6 +481,7 @@
 	if (kex == NULL)
 		return SSH_ERR_INVALID_ARGUMENT;
 
+	ssh_dispatch_set(ssh, SSH2_MSG_KEXINIT, NULL);
 	ptr = sshpkt_ptr(ssh, &dlen);
 	if ((r = sshbuf_put(kex->peer, ptr, dlen)) != 0)
 		return r;
```
