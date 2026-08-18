# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 1496_3
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1496_3`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 1843-1883 of the vulnerable file.

    int (*p_tls1_process_heartbeat) (SSL *s,
        unsigned char *p, unsigned int length);
    int (*p_dtls1_process_heartbeat) (SSL *s,
        unsigned char *p, unsigned int length);
};

# ifndef OPENSSL_UNIT_TEST

void ssl_clear_cipher_ctx(SSL *s);
int ssl_clear_bad_session(SSL *s);
__owur CERT *ssl_cert_new(void);
__owur CERT *ssl_cert_dup(CERT *cert);
void ssl_cert_clear_certs(CERT *c);
void ssl_cert_free(CERT *c);
__owur SESS_CERT *ssl_sess_cert_new(void);
void ssl_sess_cert_free(SESS_CERT *sc);
__owur int ssl_set_peer_cert_type(SESS_CERT *c, int type);
__owur int ssl_get_new_session(SSL *s, int session);
__owur int ssl_get_prev_session(SSL *s, unsigned char *session, int len,
                         const unsigned char *limit);
__owur int ssl_cipher_id_cmp(const SSL_CIPHER *a, const SSL_CIPHER *b);
DECLARE_OBJ_BSEARCH_GLOBAL_CMP_FN(SSL_CIPHER, SSL_CIPHER, ssl_cipher_id);
__owur int ssl_cipher_ptr_id_cmp(const SSL_CIPHER *const *ap,
                          const SSL_CIPHER *const *bp);
__owur STACK_OF(SSL_CIPHER) *ssl_create_cipher_list(const SSL_METHOD *meth,
                                             STACK_OF(SSL_CIPHER) **pref,
                                             STACK_OF(SSL_CIPHER) **sorted,
                                             const char *rule_str, CERT *c);
void ssl_update_cache(SSL *s, int mode);
__owur int ssl_cipher_get_evp(const SSL_SESSION *s, const EVP_CIPHER **enc,
                       const EVP_MD **md, int *mac_pkey_type,
                       int *mac_secret_size, SSL_COMP **comp, int use_etm);
__owur int ssl_get_handshake_digest(int i, long *mask, const EVP_MD **md);
__owur int ssl_cipher_get_cert_index(const SSL_CIPHER *c);
__owur const SSL_CIPHER *ssl_get_cipher_by_char(SSL *ssl, const unsigned char *ptr);
__owur int ssl_cert_set0_chain(SSL *s, SSL_CTX *ctx, STACK_OF(X509) *chain);
__owur int ssl_cert_set1_chain(SSL *s, SSL_CTX *ctx, STACK_OF(X509) *chain);
__owur int ssl_cert_add0_chain_cert(SSL *s, SSL_CTX *ctx, X509 *x);
__owur int ssl_cert_add1_chain_cert(SSL *s, SSL_CTX *ctx, X509 *x);
__owur int ssl_cert_select_current(CERT *c, X509 *x);
__owur int ssl_cert_set_current(CERT *c, long arg);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1860,6 +1860,7 @@
 __owur int ssl_get_new_session(SSL *s, int session);
 __owur int ssl_get_prev_session(SSL *s, unsigned char *session, int len,
                          const unsigned char *limit);
+__owur SSL_SESSION *ssl_session_dup(SSL_SESSION *src, int ticket);
 __owur int ssl_cipher_id_cmp(const SSL_CIPHER *a, const SSL_CIPHER *b);
 DECLARE_OBJ_BSEARCH_GLOBAL_CMP_FN(SSL_CIPHER, SSL_CIPHER, ssl_cipher_id);
 __owur int ssl_cipher_ptr_id_cmp(const SSL_CIPHER *const *ap,
```
