# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 3070_4
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3070_4`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 113-153 of the vulnerable file.

    const EVP_CIPHER *c;
#ifndef OPENSSL_NO_COMP
    const SSL_COMP *comp;
#endif
    const EVP_MD *m;
    int mac_type;
    int *mac_secret_size;
    EVP_MD_CTX *mac_ctx;
    EVP_PKEY *mac_key;
    int n, i, j, k, cl;
    int reuse_dd = 0;

    c = s->s3->tmp.new_sym_enc;
    m = s->s3->tmp.new_hash;
    mac_type = s->s3->tmp.new_mac_pkey_type;
#ifndef OPENSSL_NO_COMP
    comp = s->s3->tmp.new_compression;
#endif

    if (which & SSL3_CC_READ) {
        if (s->s3->tmp.new_cipher->algorithm2 & TLS1_STREAM_MAC)
            s->mac_flags |= SSL_MAC_FLAG_READ_MAC_STREAM;
        else
            s->mac_flags &= ~SSL_MAC_FLAG_READ_MAC_STREAM;

        if (s->enc_read_ctx != NULL)
            reuse_dd = 1;
        else if ((s->enc_read_ctx = EVP_CIPHER_CTX_new()) == NULL)
            goto err;
        else
            /*
             * make sure it's initialised in case we exit later with an error
             */
            EVP_CIPHER_CTX_reset(s->enc_read_ctx);
        dd = s->enc_read_ctx;
        mac_ctx = ssl_replace_hash(&s->read_hash, NULL);
        if (mac_ctx == NULL)
            goto err;
#ifndef OPENSSL_NO_COMP
        COMP_CTX_free(s->expand);
        s->expand = NULL;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -130,6 +130,11 @@
 #endif
 
     if (which & SSL3_CC_READ) {
+        if (s->tlsext_use_etm)
+            s->s3->flags |= TLS1_FLAGS_ENCRYPT_THEN_MAC_READ;
+        else
+            s->s3->flags &= ~TLS1_FLAGS_ENCRYPT_THEN_MAC_READ;
+
         if (s->s3->tmp.new_cipher->algorithm2 & TLS1_STREAM_MAC)
             s->mac_flags |= SSL_MAC_FLAG_READ_MAC_STREAM;
         else
@@ -168,6 +173,11 @@
         mac_secret = &(s->s3->read_mac_secret[0]);
         mac_secret_size = &(s->s3->read_mac_secret_size);
     } else {
+        if (s->tlsext_use_etm)
+            s->s3->flags |= TLS1_FLAGS_ENCRYPT_THEN_MAC_WRITE;
+        else
+            s->s3->flags &= ~TLS1_FLAGS_ENCRYPT_THEN_MAC_WRITE;
+
         if (s->s3->tmp.new_cipher->algorithm2 & TLS1_STREAM_MAC)
             s->mac_flags |= SSL_MAC_FLAG_WRITE_MAC_STREAM;
         else
@@ -367,9 +377,8 @@
     if (s->s3->tmp.key_block_length != 0)
         return (1);
 
-    if (!ssl_cipher_get_evp
-        (s->session, &c, &hash, &mac_type, &mac_secret_size, &comp,
-         SSL_USE_ETM(s))) {
+    if (!ssl_cipher_get_evp(s->session, &c, &hash, &mac_type, &mac_secret_size,
+                            &comp, s->tlsext_use_etm)) {
         SSLerr(SSL_F_TLS1_SETUP_KEY_BLOCK, SSL_R_CIPHER_OR_HASH_UNAVAILABLE);
         return (0);
     }
```
