# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 1496_4
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1496_4`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 206-246 of the vulnerable file.

    ss->time = (unsigned long)time(NULL);
    ss->prev = NULL;
    ss->next = NULL;
    ss->compress_meth = 0;
    ss->tlsext_hostname = NULL;
#ifndef OPENSSL_NO_EC
    ss->tlsext_ecpointformatlist_length = 0;
    ss->tlsext_ecpointformatlist = NULL;
    ss->tlsext_ellipticcurvelist_length = 0;
    ss->tlsext_ellipticcurvelist = NULL;
#endif
    CRYPTO_new_ex_data(CRYPTO_EX_INDEX_SSL_SESSION, ss, &ss->ex_data);
#ifndef OPENSSL_NO_PSK
    ss->psk_identity_hint = NULL;
    ss->psk_identity = NULL;
#endif
#ifndef OPENSSL_NO_SRP
    ss->srp_username = NULL;
#endif
    return (ss);
}

const unsigned char *SSL_SESSION_get_id(const SSL_SESSION *s,
                                        unsigned int *len)
{
    if (len)
        *len = s->session_id_length;
    return s->session_id;
}

unsigned int SSL_SESSION_get_compress_id(const SSL_SESSION *s)
{
    return s->compress_meth;
}

/*
 * SSLv3/TLSv1 has 32 bytes (256 bits) of session ID space. As such, filling
 * the ID with random junk repeatedly until we have no conflict is going to
 * complete in one iteration pretty much "most" of the time (btw:
 * understatement). So, if it takes us 10 iterations and we still can't avoid
 * a conflict - well that's a reasonable point to call it quits. Either the
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -223,6 +223,122 @@
     ss->srp_username = NULL;
 #endif
     return (ss);
+}
+
+/*
+ * Create a new SSL_SESSION and duplicate the contents of |src| into it. If
+ * ticket == 0 then no ticket information is duplicated, otherwise it is.
+ */
+SSL_SESSION *ssl_session_dup(SSL_SESSION *src, int ticket)
+{
+    SSL_SESSION *dest;
+
+    dest = OPENSSL_malloc(sizeof(*src));
+    if (dest == NULL) {
+        goto err;
+    }
+    memcpy(dest, src, sizeof(*dest));
+
+#ifndef OPENSSL_NO_PSK
+    if (src->psk_identity_hint) {
+        dest->psk_identity_hint = BUF_strdup(src->psk_identity_hint);
+        if (dest->psk_identity_hint == NULL) {
+            goto err;
+        }
+    } else {
+        dest->psk_identity_hint = NULL;
+    }
+    if (src->psk_identity) {
+        dest->psk_identity = BUF_strdup(src->psk_identity);
+        if (dest->psk_identity == NULL) {
+            goto err;
+        }
+    } else {
+        dest->psk_identity = NULL;
+    }
+#endif
+
+    if (src->sess_cert != NULL)
+        CRYPTO_add(&src->sess_cert->references, 1, CRYPTO_LOCK_SSL_SESS_CERT);
+
+    if (src->peer != NULL)
+        CRYPTO_add(&src->peer->references, 1, CRYPTO_LOCK_X509);
+
+    dest->references = 1;
+
+    if(src->ciphers != NULL) {
+        dest->ciphers = sk_SSL_CIPHER_dup(src->ciphers);
+        if (dest->ciphers == NULL)
+            goto err;
+    } else {
+        dest->ciphers = NULL;
+    }
+
+    if (!CRYPTO_dup_ex_data(CRYPTO_EX_INDEX_SSL_SESSION,
+                                            &dest->ex_data, &src->ex_data)) {
+        goto err;
+    }
+
+    /* We deliberately don't copy the prev and next pointers */
+    dest->prev = NULL;
+    dest->next = NULL;
+
+#ifndef OPENSSL_NO_TLSEXT
+    if (src->tlsext_hostname) {
+        dest->tlsext_hostname = BUF_strdup(src->tlsext_hostname);
+        if (dest->tlsext_hostname == NULL) {
+            goto err;
+        }
+    } else {
+        dest->tlsext_hostname = NULL;
+    }
+# ifndef OPENSSL_NO_EC
+    if (src->tlsext_ecpointformatlist) {
+        dest->tlsext_ecpointformatlist =
+            BUF_memdup(src->tlsext_ecpointformatlist,
+                       src->tlsext_ecpointformatlist_length);
+        if (dest->tlsext_ecpointformatlist == NULL)
+            goto err;
+        dest->tlsext_ecpointformatlist_length =
+            src->tlsext_ecpointformatlist_length;
+    }
+    if (src->tlsext_ellipticcurvelist) {
+        dest->tlsext_ellipticcurvelist =
+            BUF_memdup(src->tlsext_ellipticcurvelist,
+                       src->tlsext_ellipticcurvelist_length);
+        if (dest->tlsext_ellipticcurvelist == NULL)
+            goto err;
+        dest->tlsext_ellipticcurvelist_length =
+            src->tlsext_ellipticcurvelist_length;
+    }
+# endif
+#endif
+
+    if (ticket != 0) {
+        dest->tlsext_tick_lifetime_hint = src->tlsext_tick_lifetime_hint;
+        dest->tlsext_ticklen = src->tlsext_ticklen;
+        if((dest->tlsext_tick = OPENSSL_malloc(src->tlsext_ticklen)) == NULL) {
+            goto err;
+        }
+    }
+
+#ifndef OPENSSL_NO_SRP
+    dest->srp_username = NULL;
+    if (src->srp_username) {
+        dest->srp_username = BUF_strdup(src->srp_username);
+        if (dest->srp_username == NULL) {
+            goto err;
+        }
+    } else {
+        dest->srp_username = NULL;
+    }
+#endif
+
+    return dest;
+err:
+    SSLerr(SSL_F_SSL_SESSION_DUP, ERR_R_MALLOC_FAILURE);
+    SSL_SESSION_free(dest);
+    return NULL;
 }
 
 const unsigned char *SSL_SESSION_get_id(const SSL_SESSION *s,
```
