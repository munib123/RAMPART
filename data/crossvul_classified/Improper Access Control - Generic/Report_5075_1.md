# CrossVul Fix Pair: Improper Access Control in c
**Pair ID:** 5075_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5075_1`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```c
Lines 710-750 of the vulnerable file.

        SSL_set_verify_result(ssl, X509_V_OK);

        /* determine whether we've to force a renegotiation */
        if (!renegotiate && verify != verify_old) {
            if (((verify_old == SSL_VERIFY_NONE) &&
                 (verify     != SSL_VERIFY_NONE)) ||

                (!(verify_old & SSL_VERIFY_PEER) &&
                  (verify     & SSL_VERIFY_PEER)) ||

                (!(verify_old & SSL_VERIFY_FAIL_IF_NO_PEER_CERT) &&
                  (verify     & SSL_VERIFY_FAIL_IF_NO_PEER_CERT)))
            {
                renegotiate = TRUE;
                if (is_slave) {
                    /* The request causes renegotiation on a slave connection.
                     * This is not allowed since we might have concurrent requests
                     * on this connection.
                     */
                    apr_table_setn(r->notes, "ssl-renegotiate-forbidden", "verify-client");
                    return HTTP_FORBIDDEN;
                }
                /* optimization */

                if ((dc->nOptions & SSL_OPT_OPTRENEGOTIATE) &&
                    (verify_old == SSL_VERIFY_NONE) &&
                    ((peercert = SSL_get_peer_certificate(ssl)) != NULL))
                {
                    renegotiate_quick = TRUE;
                    X509_free(peercert);
                }

                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(02255)
                              "Changed client verification type will force "
                              "%srenegotiation",
                              renegotiate_quick ? "quick " : "");
            }
            else if (verify != SSL_VERIFY_NONE) {
                /*
                 * override of SSLVerifyDepth
                 *
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -727,6 +727,7 @@
                      * on this connection.
                      */
                     apr_table_setn(r->notes, "ssl-renegotiate-forbidden", "verify-client");
+                    SSL_set_verify(ssl, verify_old, ssl_callback_SSLVerify);
                     return HTTP_FORBIDDEN;
                 }
                 /* optimization */
```
