# CrossVul Fix Pair: Improper Verification of Cryptographic Signature in c
**Pair ID:** 327_1
**Vulnerability Class:** Improper Verification of Cryptographic Signature
**CWE:** CWE-347
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `327_1`)

## Vulnerability Information & PoC

## Description
Improper Verification of Cryptographic Signature - The product does not verify, or incorrectly verifies, the cryptographic signature for data.

## Vulnerable Code
```c
Lines 32-91 of the vulnerable file.

 * @file x509.c
 * 
 * Certificate processing.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include "os_port.h"
#include "crypto_misc.h"

#ifdef CONFIG_SSL_CERT_VERIFICATION
static int x509_v3_subject_alt_name(const uint8_t *cert, int offset, 
        X509_CTX *x509_ctx);
static int x509_v3_basic_constraints(const uint8_t *cert, int offset, 
        X509_CTX *x509_ctx);
static int x509_v3_key_usage(const uint8_t *cert, int offset, 
        X509_CTX *x509_ctx);

/**
 * Retrieve the signature from a certificate.
 */
static const uint8_t *get_signature(const uint8_t *asn1_sig, int *len)
{
    int offset = 0;
    const uint8_t *ptr = NULL;

    if (asn1_next_obj(asn1_sig, &offset, ASN1_SEQUENCE) < 0 || 
            asn1_skip_obj(asn1_sig, &offset, ASN1_SEQUENCE))
        goto end_get_sig;

    if (asn1_sig[offset++] != ASN1_OCTET_STRING)
        goto end_get_sig;
    *len = get_asn1_length(asn1_sig, &offset);
    ptr = &asn1_sig[offset];          /* all ok */

end_get_sig:
    return ptr;
}

#endif

/**
 * Construct a new x509 object.
 * @return 0 if ok. < 0 if there was a problem.
 */
int x509_new(const uint8_t *cert, int *len, X509_CTX **ctx)
{
    int begin_tbs, end_tbs, begin_spki, end_spki;
    int ret = X509_NOT_OK, offset = 0, cert_size = 0;
    int version = 0;
    X509_CTX *x509_ctx;
#ifdef CONFIG_SSL_CERT_VERIFICATION /* only care if doing verification */
    BI_CTX *bi_ctx;
#endif

    *ctx = (X509_CTX *)calloc(1, sizeof(X509_CTX));
    x509_ctx = *ctx;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -49,28 +49,6 @@
         X509_CTX *x509_ctx);
 static int x509_v3_key_usage(const uint8_t *cert, int offset, 
         X509_CTX *x509_ctx);
-
-/**
- * Retrieve the signature from a certificate.
- */
-static const uint8_t *get_signature(const uint8_t *asn1_sig, int *len)
-{
-    int offset = 0;
-    const uint8_t *ptr = NULL;
-
-    if (asn1_next_obj(asn1_sig, &offset, ASN1_SEQUENCE) < 0 || 
-            asn1_skip_obj(asn1_sig, &offset, ASN1_SEQUENCE))
-        goto end_get_sig;
-
-    if (asn1_sig[offset++] != ASN1_OCTET_STRING)
-        goto end_get_sig;
-    *len = get_asn1_length(asn1_sig, &offset);
-    ptr = &asn1_sig[offset];          /* all ok */
-
-end_get_sig:
-    return ptr;
-}
-
 #endif
 
 /**
@@ -412,17 +390,56 @@
 }
 
 #ifdef CONFIG_SSL_CERT_VERIFICATION
+static const uint8_t sig_prefix_md5[] PROGMEM = {0x30, 0x20, 0x30, 0x0C, 0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10};
+static const uint8_t sig_prefix_sha1[] PROGMEM = {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14};
+static const uint8_t sig_prefix_sha256[] PROGMEM = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
+static const uint8_t sig_prefix_sha384[] PROGMEM = {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30};
+static const uint8_t sig_prefix_sha512[] PROGMEM = {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40};
+
 /**
  * Take a signature and decrypt it.
  */
-static bigint *sig_verify(BI_CTX *ctx, const uint8_t *sig, int sig_len,
+static bigint *sig_verify(BI_CTX *ctx, const uint8_t *sig, int sig_len, uint8_t sig_type,
         bigint *modulus, bigint *pub_exp)
 {
-    int i, size;
+    int i;
     bigint *decrypted_bi, *dat_bi;
     bigint *bir = NULL;
     uint8_t *block = (uint8_t *)malloc(sig_len);
 
+    const uint8_t *sig_prefix = NULL;
+    uint8_t sig_prefix_size = 0, hash_len = 0;
+    /* adjust our expections */
+    switch (sig_type)
+    {
+        case SIG_TYPE_MD5:
+            sig_prefix = sig_prefix_md5;
+            sig_prefix_size = sizeof(sig_prefix_md5);
+        break;
+        case SIG_TYPE_SHA1:
+            sig_prefix = sig_prefix_sha1;
+            sig_prefix_size = sizeof(sig_prefix_sha1);
+        break;
+        case SIG_TYPE_SHA256:
+            sig_prefix = sig_prefix_sha256;
+            sig_prefix_size = sizeof(sig_prefix_sha256);
+        break;
+        case SIG_TYPE_SHA384:
+            sig_prefix = sig_prefix_sha384;
+            sig_prefix_size = sizeof(sig_prefix_sha384);
+        break;
+        case SIG_TYPE_SHA512:
+            sig_prefix = sig_prefix_sha512;
+            sig_prefix_size = sizeof(sig_prefix_sha512);
+        break;
+    }
+    if (sig_prefix)
+        hash_len = sig_prefix[sig_prefix_size - 1];
+
+    /* check length (#A) */
+    if (sig_len < 2 + 8 + 1 + sig_prefix_size + hash_len)
+        goto err;
+
     /* decrypt */
     dat_bi = bi_import(ctx, sig, sig_len);
     ctx->mod_offset = BIGINT_M_OFFSET;
@@ -433,21 +450,30 @@
     bi_export(ctx, decrypted_bi, block, sig_len);
     ctx->mod_offset = BIGINT_M_OFFSET;
 
-    i = 10; /* start at the first possible non-padded byte */
-    while (block[i++] && i < sig_len);
-    size = sig_len - i;
-
-    /* get only the bit we want */
-    if (size > 0)
-    {
-        int len;
-        const uint8_t *sig_ptr = get_signature(&block[i], &len);
-
-        if (sig_ptr)
-        {
-            bir = bi_import(ctx, sig_ptr, len);
-        }
-    }
+    /* check the first 2 bytes */
+    if (block[0] != 0 || block[1] != 1)
+        goto err;
+
+    /* check the padding */
+    i = 2; /* start at the first padding byte */
+    while (i < sig_len - 1 - sig_prefix_size - hash_len)
+    { /* together with (#A), we require at least 8 bytes of padding */
+        if (block[i++] != 0xFF)
+            goto err;
+    }
+
+    /* check end of padding */
+    if (block[i++] != 0)
+        goto err;
+
+    /* check the ASN.1 metadata */
+    if (memcmp_P(block+i, sig_prefix, sig_prefix_size))
+        goto err;
+
+    /* now we can get the hash we need */
+    bir = bi_import(ctx, block + i + sig_prefix_size, hash_len);
+
+err:
     free(block);
     /* save a few bytes of memory */
     bi_clear_cache(ctx);
@@ -600,7 +626,7 @@
     }
 
     /* check the signature */
-    cert_sig = sig_verify(ctx, cert->signature, cert->sig_len, 
+    cert_sig = sig_verify(ctx, cert->signature, cert->sig_len, cert->sig_type,
                         bi_clone(ctx, mod), bi_clone(ctx, expn));
 
     if (cert_sig && cert->digest)
```
