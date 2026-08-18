# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 1496_1
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1496_1`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 2221-2261 of the vulnerable file.

    long n;
    const unsigned char *p;
    unsigned char *d;

    n = s->method->ssl_get_message(s,
                                   SSL3_ST_CR_SESSION_TICKET_A,
                                   SSL3_ST_CR_SESSION_TICKET_B,
                                   SSL3_MT_NEWSESSION_TICKET, 16384, &ok);

    if (!ok)
        return ((int)n);

    if (n < 6) {
        /* need at least ticket_lifetime_hint + ticket length */
        al = SSL_AD_DECODE_ERROR;
        SSLerr(SSL_F_SSL3_GET_NEW_SESSION_TICKET, SSL_R_LENGTH_MISMATCH);
        goto f_err;
    }

    p = d = (unsigned char *)s->init_msg;
    n2l(p, s->session->tlsext_tick_lifetime_hint);
    n2s(p, ticklen);
    /* ticket_lifetime_hint + ticket_length + ticket */
    if (ticklen + 6 != n) {
        al = SSL_AD_DECODE_ERROR;
        SSLerr(SSL_F_SSL3_GET_NEW_SESSION_TICKET, SSL_R_LENGTH_MISMATCH);
        goto f_err;
    }
    OPENSSL_free(s->session->tlsext_tick);
    s->session->tlsext_ticklen = 0;
    s->session->tlsext_tick = OPENSSL_malloc(ticklen);
    if (!s->session->tlsext_tick) {
        SSLerr(SSL_F_SSL3_GET_NEW_SESSION_TICKET, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    memcpy(s->session->tlsext_tick, p, ticklen);
    s->session->tlsext_ticklen = ticklen;
    /*
     * There are two ways to detect a resumed ticket session. One is to set
     * an appropriate session ID and then the server must return a match in
     * ServerHello. This allows the normal client session ID matching to work
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2238,6 +2238,38 @@
     }
 
     p = d = (unsigned char *)s->init_msg;
+
+    if (s->session->session_id_length > 0) {
+        int i = s->session_ctx->session_cache_mode;
+        SSL_SESSION *new_sess;
+        /*
+         * We reused an existing session, so we need to replace it with a new
+         * one
+         */
+        if (i & SSL_SESS_CACHE_CLIENT) {
+            /*
+             * Remove the old session from the cache
+             */
+            if (i & SSL_SESS_CACHE_NO_INTERNAL_STORE) {
+                if (s->session_ctx->remove_session_cb != NULL)
+                    s->session_ctx->remove_session_cb(s->session_ctx,
+                                                      s->session);
+            } else {
+                /* We carry on if this fails */
+                SSL_CTX_remove_session(s->session_ctx, s->session);
+            }
+        }
+
+        if ((new_sess = ssl_session_dup(s->session, 0)) == 0) {
+            al = SSL_AD_INTERNAL_ERROR;
+            SSLerr(SSL_F_SSL3_GET_NEW_SESSION_TICKET, ERR_R_MALLOC_FAILURE);
+            goto f_err;
+        }
+
+        SSL_SESSION_free(s->session);
+        s->session = new_sess;
+    }
+
     n2l(p, s->session->tlsext_tick_lifetime_hint);
     n2s(p, ticklen);
     /* ticket_lifetime_hint + ticket_length + ticket */
```
