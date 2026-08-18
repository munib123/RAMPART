# CrossVul Fix Pair: Improper Certificate Validation in c
**Pair ID:** 682_0
**Vulnerability Class:** Improper Certificate Validation
**CWE:** CWE-295
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `682_0`)

## Vulnerability Information & PoC

## Description
Improper Certificate Validation - When a certificate is invalid or malicious, it might allow an attacker to spoof a trusted entity by interfering in the communication path between the host and client.

## Vulnerable Code
```c
Lines 1-21 of the vulnerable file.

/* $OpenBSD: x509_vpm.c,v 1.16 2017/12/09 07:09:25 deraadt Exp $ */
/* Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project 2004.
 */
/* ====================================================================
 * Copyright (c) 2004 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,4 +1,4 @@
-/* $OpenBSD: x509_vpm.c,v 1.16 2017/12/09 07:09:25 deraadt Exp $ */
+/* $OpenBSD: x509_vpm.c,v 1.17 2018/03/22 15:54:46 beck Exp $ */
 /* Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
  * project 2004.
  */
@@ -130,6 +130,8 @@
 {
 	char *copy;
 
+	if (name != NULL && namelen == 0)
+		namelen = strlen(name);
 	/*
 	 * Refuse names with embedded NUL bytes.
 	 * XXX: Do we need to push an error onto the error stack?
```
