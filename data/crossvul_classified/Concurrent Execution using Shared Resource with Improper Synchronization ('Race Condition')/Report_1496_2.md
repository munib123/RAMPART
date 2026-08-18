# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 1496_2
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1496_2`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 257-297 of the vulnerable file.

    {ERR_FUNC(SSL_F_SSL_PARSE_CLIENTHELLO_TLSEXT),
     "ssl_parse_clienthello_tlsext"},
    {ERR_FUNC(SSL_F_SSL_PARSE_CLIENTHELLO_USE_SRTP_EXT),
     "ssl_parse_clienthello_use_srtp_ext"},
    {ERR_FUNC(SSL_F_SSL_PARSE_SERVERHELLO_RENEGOTIATE_EXT),
     "ssl_parse_serverhello_renegotiate_ext"},
    {ERR_FUNC(SSL_F_SSL_PARSE_SERVERHELLO_TLSEXT),
     "ssl_parse_serverhello_tlsext"},
    {ERR_FUNC(SSL_F_SSL_PARSE_SERVERHELLO_USE_SRTP_EXT),
     "ssl_parse_serverhello_use_srtp_ext"},
    {ERR_FUNC(SSL_F_SSL_PEEK), "SSL_peek"},
    {ERR_FUNC(SSL_F_SSL_PREPARE_CLIENTHELLO_TLSEXT),
     "ssl_prepare_clienthello_tlsext"},
    {ERR_FUNC(SSL_F_SSL_PREPARE_SERVERHELLO_TLSEXT),
     "ssl_prepare_serverhello_tlsext"},
    {ERR_FUNC(SSL_F_SSL_READ), "SSL_read"},
    {ERR_FUNC(SSL_F_SSL_SCAN_CLIENTHELLO_TLSEXT),
     "SSL_SCAN_CLIENTHELLO_TLSEXT"},
    {ERR_FUNC(SSL_F_SSL_SCAN_SERVERHELLO_TLSEXT),
     "SSL_SCAN_SERVERHELLO_TLSEXT"},
    {ERR_FUNC(SSL_F_SSL_SESSION_NEW), "SSL_SESSION_new"},
    {ERR_FUNC(SSL_F_SSL_SESSION_PRINT_FP), "SSL_SESSION_print_fp"},
    {ERR_FUNC(SSL_F_SSL_SESSION_SET1_ID_CONTEXT),
     "SSL_SESSION_set1_id_context"},
    {ERR_FUNC(SSL_F_SSL_SESS_CERT_NEW), "ssl_sess_cert_new"},
    {ERR_FUNC(SSL_F_SSL_SET_CERT), "SSL_SET_CERT"},
    {ERR_FUNC(SSL_F_SSL_SET_CIPHER_LIST), "SSL_set_cipher_list"},
    {ERR_FUNC(SSL_F_SSL_SET_FD), "SSL_set_fd"},
    {ERR_FUNC(SSL_F_SSL_SET_PKEY), "SSL_SET_PKEY"},
    {ERR_FUNC(SSL_F_SSL_SET_PURPOSE), "SSL_set_purpose"},
    {ERR_FUNC(SSL_F_SSL_SET_RFD), "SSL_set_rfd"},
    {ERR_FUNC(SSL_F_SSL_SET_SESSION), "SSL_set_session"},
    {ERR_FUNC(SSL_F_SSL_SET_SESSION_ID_CONTEXT), "SSL_set_session_id_context"},
    {ERR_FUNC(SSL_F_SSL_SET_SESSION_TICKET_EXT), "SSL_set_session_ticket_ext"},
    {ERR_FUNC(SSL_F_SSL_SET_TRUST), "SSL_set_trust"},
    {ERR_FUNC(SSL_F_SSL_SET_VERSION), "SSL_SET_VERSION"},
    {ERR_FUNC(SSL_F_SSL_SET_WFD), "SSL_set_wfd"},
    {ERR_FUNC(SSL_F_SSL_SHUTDOWN), "SSL_shutdown"},
    {ERR_FUNC(SSL_F_SSL_SRP_CTX_INIT), "SSL_SRP_CTX_init"},
    {ERR_FUNC(SSL_F_SSL_UNDEFINED_CONST_FUNCTION),
     "ssl_undefined_const_function"},
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -274,6 +274,7 @@
      "SSL_SCAN_CLIENTHELLO_TLSEXT"},
     {ERR_FUNC(SSL_F_SSL_SCAN_SERVERHELLO_TLSEXT),
      "SSL_SCAN_SERVERHELLO_TLSEXT"},
+    {ERR_FUNC(SSL_F_SSL_SESSION_DUP), "ssl_session_dup"},
     {ERR_FUNC(SSL_F_SSL_SESSION_NEW), "SSL_SESSION_new"},
     {ERR_FUNC(SSL_F_SSL_SESSION_PRINT_FP), "SSL_SESSION_print_fp"},
     {ERR_FUNC(SSL_F_SSL_SESSION_SET1_ID_CONTEXT),
```
