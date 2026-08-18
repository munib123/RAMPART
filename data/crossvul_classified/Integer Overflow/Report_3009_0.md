# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 3009_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3009_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 3419-3459 of the vulnerable file.

          MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED */

#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
static int ssl_parse_client_psk_identity( mbedtls_ssl_context *ssl, unsigned char **p,
                                          const unsigned char *end )
{
    int ret = 0;
    size_t n;

    if( ssl->conf->f_psk == NULL &&
        ( ssl->conf->psk == NULL || ssl->conf->psk_identity == NULL ||
          ssl->conf->psk_identity_len == 0 || ssl->conf->psk_len == 0 ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "got no pre-shared key" ) );
        return( MBEDTLS_ERR_SSL_PRIVATE_KEY_REQUIRED );
    }

    /*
     * Receive client pre-shared key identity name
     */
    if( *p + 2 > end )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad client key exchange message" ) );
        return( MBEDTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE );
    }

    n = ( (*p)[0] << 8 ) | (*p)[1];
    *p += 2;

    if( n < 1 || n > 65535 || *p + n > end )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad client key exchange message" ) );
        return( MBEDTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE );
    }

    if( ssl->conf->f_psk != NULL )
    {
        if( ssl->conf->f_psk( ssl->conf->p_psk, ssl, *p, n ) != 0 )
            ret = MBEDTLS_ERR_SSL_UNKNOWN_IDENTITY;
    }
    else
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3436,7 +3436,7 @@
     /*
      * Receive client pre-shared key identity name
      */
-    if( *p + 2 > end )
+    if( end - *p < 2 )
     {
         MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad client key exchange message" ) );
         return( MBEDTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE );
@@ -3445,7 +3445,7 @@
     n = ( (*p)[0] << 8 ) | (*p)[1];
     *p += 2;
 
-    if( n < 1 || n > 65535 || *p + n > end )
+    if( n < 1 || n > 65535 || n > (size_t) ( end - *p ) )
     {
         MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad client key exchange message" ) );
         return( MBEDTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE );
```
