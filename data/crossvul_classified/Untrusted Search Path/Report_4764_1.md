# CrossVul Fix Pair: Untrusted Search Path in c
**Pair ID:** 4764_1
**Vulnerability Class:** Untrusted Search Path
**CWE:** CWE-426
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4764_1`)

## Vulnerability Information & PoC

## Description
Untrusted Search Path - This might allow attackers to execute their own programs, access unauthorized data files, or modify configuration in unexpected ways.

## Vulnerable Code
```c
Lines 1-21 of the vulnerable file.

/* $OpenBSD: ssh-agent.c,v 1.214 2016/09/12 01:22:38 deraadt Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * The authentication agent program.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 * Copyright (c) 2000, 2001 Markus Friedl.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,4 +1,4 @@
-/* $OpenBSD: ssh-agent.c,v 1.214 2016/09/12 01:22:38 deraadt Exp $ */
+/* $OpenBSD: ssh-agent.c,v 1.215 2016/11/30 03:07:37 djm Exp $ */
 /*
  * Author: Tatu Ylonen <ylo@cs.hut.fi>
  * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
@@ -69,9 +69,14 @@
 #include "misc.h"
 #include "digest.h"
 #include "ssherr.h"
+#include "match.h"
 
 #ifdef ENABLE_PKCS11
 #include "ssh-pkcs11.h"
+#endif
+
+#ifndef DEFAULT_PKCS11_WHITELIST
+# define DEFAULT_PKCS11_WHITELIST "/usr/lib/*,/usr/local/lib/*"
 #endif
 
 typedef enum {
@@ -120,6 +125,9 @@
 /* pathname and directory for AUTH_SOCKET */
 char socket_name[PATH_MAX];
 char socket_dir[PATH_MAX];
+
+/* PKCS#11 path whitelist */
+static char *pkcs11_whitelist;
 
 /* locking */
 #define LOCK_SIZE	32
@@ -724,7 +732,7 @@
 static void
 process_add_smartcard_key(SocketEntry *e)
 {
-	char *provider = NULL, *pin;
+	char *provider = NULL, *pin, canonical_provider[PATH_MAX];
 	int r, i, version, count = 0, success = 0, confirm = 0;
 	u_int seconds;
 	time_t death = 0;
@@ -756,10 +764,21 @@
 			goto send;
 		}
 	}
+	if (realpath(provider, canonical_provider) == NULL) {
+		verbose("failed PKCS#11 add of \"%.100s\": realpath: %s",
+		    provider, strerror(errno));
+		goto send;
+	}
+	if (match_pattern_list(canonical_provider, pkcs11_whitelist, 0) != 1) {
+		verbose("refusing PKCS#11 add of \"%.100s\": "
+		    "provider not whitelisted", canonical_provider);
+		goto send;
+	}
+	debug("%s: add %.100s", __func__, canonical_provider);
 	if (lifetime && !death)
 		death = monotime() + lifetime;
 
-	count = pkcs11_add_provider(provider, pin, &keys);
+	count = pkcs11_add_provider(canonical_provider, pin, &keys);
 	for (i = 0; i < count; i++) {
 		k = keys[i];
 		version = k->type == KEY_RSA1 ? 1 : 2;
@@ -767,8 +786,8 @@
 		if (lookup_identity(k, version) == NULL) {
 			id = xcalloc(1, sizeof(Identity));
 			id->key = k;
-			id->provider = xstrdup(provider);
-			id->comment = xstrdup(provider); /* XXX */
+			id->provider = xstrdup(canonical_provider);
+			id->comment = xstrdup(canonical_provider); /* XXX */
 			id->death = death;
 			id->confirm = confirm;
 			TAILQ_INSERT_TAIL(&tab->idlist, id, next);
@@ -1157,7 +1176,7 @@
 {
 	fprintf(stderr,
 	    "usage: ssh-agent [-c | -s] [-Dd] [-a bind_address] [-E fingerprint_hash]\n"
-	    "                 [-t life] [command [arg ...]]\n"
+	    "                 [-P pkcs11_whitelist] [-t life] [command [arg ...]]\n"
 	    "       ssh-agent [-c | -s] -k\n");
 	exit(1);
 }
@@ -1191,7 +1210,7 @@
 	OpenSSL_add_all_algorithms();
 #endif
 
-	while ((ch = getopt(ac, av, "cDdksE:a:t:")) != -1) {
+	while ((ch = getopt(ac, av, "cDdksE:a:P:t:")) != -1) {
 		switch (ch) {
 		case 'E':
 			fingerprint_hash = ssh_digest_alg_by_name(optarg);
@@ -1206,6 +1225,11 @@
 		case 'k':
 			k_flag++;
 			break;
+		case 'P':
+			if (pkcs11_whitelist != NULL)
+				fatal("-P option already specified");
+			pkcs11_whitelist = xstrdup(optarg);
+			break;
 		case 's':
 			if (c_flag)
 				usage();
@@ -1239,6 +1263,9 @@
 
 	if (ac > 0 && (c_flag || k_flag || s_flag || d_flag || D_flag))
 		usage();
+
+	if (pkcs11_whitelist == NULL)
+		pkcs11_whitelist = xstrdup(DEFAULT_PKCS11_WHITELIST);
 
 	if (ac == 0 && !c_flag && !s_flag) {
 		shell = getenv("SHELL");
@@ -1385,7 +1412,7 @@
 	signal(SIGTERM, cleanup_handler);
 	nalloc = 0;
 
-	if (pledge("stdio cpath unix id proc exec", NULL) == -1)
+	if (pledge("stdio rpath cpath unix id proc exec", NULL) == -1)
 		fatal("%s: pledge: %s", __progname, strerror(errno));
 
 	while (1) {
```
