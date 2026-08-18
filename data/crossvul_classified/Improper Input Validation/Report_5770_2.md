# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5770_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5770_2`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 2358-2399 of the vulnerable file.

    i = 7;

    while( i < ssl->in_hslen )
    {
        if( ssl->in_msg[i] != 0 )
        {
            SSL_DEBUG_MSG( 1, ( "bad certificate message" ) );
            return( POLARSSL_ERR_SSL_BAD_HS_CERTIFICATE );
        }

        n = ( (unsigned int) ssl->in_msg[i + 1] << 8 )
            | (unsigned int) ssl->in_msg[i + 2];
        i += 3;

        if( n < 128 || i + n > ssl->in_hslen )
        {
            SSL_DEBUG_MSG( 1, ( "bad certificate message" ) );
            return( POLARSSL_ERR_SSL_BAD_HS_CERTIFICATE );
        }

        ret = x509parse_crt( ssl->session_negotiate->peer_cert, ssl->in_msg + i,
                             n );
        if( ret != 0 )
        {
            SSL_DEBUG_RET( 1, " x509parse_crt", ret );
            return( ret );
        }

        i += n;
    }

    SSL_DEBUG_CRT( 3, "peer certificate", ssl->session_negotiate->peer_cert );

    if( ssl->authmode != SSL_VERIFY_NONE )
    {
        if( ssl->ca_chain == NULL )
        {
            SSL_DEBUG_MSG( 1, ( "got no CA chain" ) );
            return( POLARSSL_ERR_SSL_CA_CHAIN_REQUIRED );
        }

        ret = x509parse_verify( ssl->session_negotiate->peer_cert,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2375,8 +2375,8 @@
             return( POLARSSL_ERR_SSL_BAD_HS_CERTIFICATE );
         }
 
-        ret = x509parse_crt( ssl->session_negotiate->peer_cert, ssl->in_msg + i,
-                             n );
+        ret = x509parse_crt_der( ssl->session_negotiate->peer_cert,
+                                 ssl->in_msg + i, n );
         if( ret != 0 )
         {
             SSL_DEBUG_RET( 1, " x509parse_crt", ret );
```
