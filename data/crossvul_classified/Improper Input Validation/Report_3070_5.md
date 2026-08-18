# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 3070_5
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3070_5`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 1657-1697 of the vulnerable file.

                                              s->
                                              ctx->next_protos_advertised_cb_arg);
        if (r == SSL_TLSEXT_ERR_OK) {
            /*-
             * check for enough space.
             * 4 bytes for the NPN type and extension length
             * + length of protocols list
             */
            if (CHECKLEN(ret, 4 + npalen, limit))
                return NULL;
            s2n(TLSEXT_TYPE_next_proto_neg, ret);
            s2n(npalen, ret);
            memcpy(ret, npa, npalen);
            ret += npalen;
            s->s3->next_proto_neg_seen = 1;
        }
    }
#endif
    if (!custom_ext_add(s, 1, &ret, limit, al))
        return NULL;
    if (s->s3->flags & TLS1_FLAGS_ENCRYPT_THEN_MAC) {
        /*
         * Don't use encrypt_then_mac if AEAD or RC4 might want to disable
         * for other cases too.
         */
        if (SSL_IS_DTLS(s) || s->s3->tmp.new_cipher->algorithm_mac == SSL_AEAD
            || s->s3->tmp.new_cipher->algorithm_enc == SSL_RC4
            || s->s3->tmp.new_cipher->algorithm_enc == SSL_eGOST2814789CNT
            || s->s3->tmp.new_cipher->algorithm_enc == SSL_eGOST2814789CNT12)
            s->s3->flags &= ~TLS1_FLAGS_ENCRYPT_THEN_MAC;
        else {
            /*-
             * check for enough space.
             * 4 bytes for the ETM type and extension length
             */
            if (CHECKLEN(ret, 4, limit))
                return NULL;
            s2n(TLSEXT_TYPE_encrypt_then_mac, ret);
            s2n(0, ret);
        }
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1674,7 +1674,7 @@
 #endif
     if (!custom_ext_add(s, 1, &ret, limit, al))
         return NULL;
-    if (s->s3->flags & TLS1_FLAGS_ENCRYPT_THEN_MAC) {
+    if (s->tlsext_use_etm) {
         /*
          * Don't use encrypt_then_mac if AEAD or RC4 might want to disable
          * for other cases too.
@@ -1683,7 +1683,7 @@
             || s->s3->tmp.new_cipher->algorithm_enc == SSL_RC4
             || s->s3->tmp.new_cipher->algorithm_enc == SSL_eGOST2814789CNT
             || s->s3->tmp.new_cipher->algorithm_enc == SSL_eGOST2814789CNT12)
-            s->s3->flags &= ~TLS1_FLAGS_ENCRYPT_THEN_MAC;
+            s->tlsext_use_etm = 0;
         else {
             /*-
              * check for enough space.
@@ -1916,7 +1916,7 @@
     /* Clear any signature algorithms extension received */
     OPENSSL_free(s->s3->tmp.peer_sigalgs);
     s->s3->tmp.peer_sigalgs = NULL;
-    s->s3->flags &= ~TLS1_FLAGS_ENCRYPT_THEN_MAC;
+    s->tlsext_use_etm = 0;
 
 #ifndef OPENSSL_NO_SRP
     OPENSSL_free(s->srp_ctx.login);
@@ -2264,7 +2264,7 @@
         }
 #endif
         else if (type == TLSEXT_TYPE_encrypt_then_mac)
-            s->s3->flags |= TLS1_FLAGS_ENCRYPT_THEN_MAC;
+            s->tlsext_use_etm = 1;
         /*
          * Note: extended master secret extension handled in
          * tls_check_serverhello_tlsext_early()
@@ -2366,7 +2366,7 @@
                              SSL_DTLSEXT_HB_DONT_SEND_REQUESTS);
 #endif
 
-    s->s3->flags &= ~TLS1_FLAGS_ENCRYPT_THEN_MAC;
+    s->tlsext_use_etm = 0;
 
     s->s3->flags &= ~TLS1_FLAGS_RECEIVED_EXTMS;
 
@@ -2585,7 +2585,7 @@
             /* Ignore if inappropriate ciphersuite */
             if (s->s3->tmp.new_cipher->algorithm_mac != SSL_AEAD
                 && s->s3->tmp.new_cipher->algorithm_enc != SSL_RC4)
-                s->s3->flags |= TLS1_FLAGS_ENCRYPT_THEN_MAC;
+                s->tlsext_use_etm = 1;
         } else if (type == TLSEXT_TYPE_extended_master_secret) {
             s->s3->flags |= TLS1_FLAGS_RECEIVED_EXTMS;
             if (!s->hit)
```
