# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 1066_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1066_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 14-54 of the vulnerable file.

 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef PACKAGE
#define PACKAGE "pam_p11"
#endif

#include <syslog.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/crypto.h>
#include <libp11.h>
#include <regex.h>

/* openssl deprecated API emulation */
#ifndef HAVE_EVP_MD_CTX_NEW
#define EVP_MD_CTX_new()	EVP_MD_CTX_create()
#endif
#ifndef HAVE_EVP_MD_CTX_FREE
#define EVP_MD_CTX_free(ctx)	EVP_MD_CTX_destroy((ctx))
#endif
#ifndef HAVE_EVP_MD_CTX_RESET
#define EVP_MD_CTX_reset(ctx)	EVP_MD_CTX_cleanup((ctx))
#endif

#ifdef ENABLE_NLS
#include <libintl.h>
#include <locale.h>
#define _(string) gettext(string)
#ifndef LOCALEDIR
#define LOCALEDIR "/usr/share/locale"
#endif
#else
#define _(string) string
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -31,6 +31,7 @@
 #include <openssl/crypto.h>
 #include <libp11.h>
 #include <regex.h>
+#include <stdlib.h>
 
 /* openssl deprecated API emulation */
 #ifndef HAVE_EVP_MD_CTX_NEW
@@ -634,12 +635,21 @@
 {
 	int ok = 0;
 	unsigned char challenge[30];
-	unsigned char signature[256];
-	unsigned int siglen = sizeof signature;
+	unsigned char *signature = NULL;
+	unsigned int siglen;
 	const EVP_MD *md = EVP_sha1();
 	EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
 	EVP_PKEY *privkey = PKCS11_get_private_key(authkey);
 	EVP_PKEY *pubkey = PKCS11_get_public_key(authkey);
+
+	if (NULL == privkey)
+		goto err;
+	siglen = EVP_PKEY_size(privkey);
+	if (siglen <= 0)
+		goto err;
+	signature = malloc(siglen);
+	if (NULL == signature)
+		goto err;
 
 	/* Verify a SHA-1 hash of random data, signed by the key.
 	 *
@@ -667,6 +677,7 @@
 	ok = 1;
 
 err:
+	free(signature);
 	if (NULL != pubkey)
 		EVP_PKEY_free(pubkey);
 	if (NULL != privkey)
```
