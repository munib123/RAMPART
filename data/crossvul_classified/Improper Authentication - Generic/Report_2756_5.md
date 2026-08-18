# CrossVul Fix Pair: Improper Authentication in c
**Pair ID:** 2756_5
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2756_5`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```c
Lines 463-503 of the vulnerable file.

        if( use_ret == -(MBEDTLS_ERR_X509_INVALID_EXTENSIONS) )
            mbedtls_snprintf( buf, buflen, "X509 - The extension tag or value is invalid" );
        if( use_ret == -(MBEDTLS_ERR_X509_UNKNOWN_VERSION) )
            mbedtls_snprintf( buf, buflen, "X509 - CRT/CRL/CSR has an unsupported version number" );
        if( use_ret == -(MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG) )
            mbedtls_snprintf( buf, buflen, "X509 - Signature algorithm (oid) is unsupported" );
        if( use_ret == -(MBEDTLS_ERR_X509_SIG_MISMATCH) )
            mbedtls_snprintf( buf, buflen, "X509 - Signature algorithms do not match. (see \\c ::mbedtls_x509_crt sig_oid)" );
        if( use_ret == -(MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) )
            mbedtls_snprintf( buf, buflen, "X509 - Certificate verification failed, e.g. CRL, CA or signature check failed" );
        if( use_ret == -(MBEDTLS_ERR_X509_CERT_UNKNOWN_FORMAT) )
            mbedtls_snprintf( buf, buflen, "X509 - Format not recognized as DER or PEM" );
        if( use_ret == -(MBEDTLS_ERR_X509_BAD_INPUT_DATA) )
            mbedtls_snprintf( buf, buflen, "X509 - Input invalid" );
        if( use_ret == -(MBEDTLS_ERR_X509_ALLOC_FAILED) )
            mbedtls_snprintf( buf, buflen, "X509 - Allocation of memory failed" );
        if( use_ret == -(MBEDTLS_ERR_X509_FILE_IO_ERROR) )
            mbedtls_snprintf( buf, buflen, "X509 - Read/write of file failed" );
        if( use_ret == -(MBEDTLS_ERR_X509_BUFFER_TOO_SMALL) )
            mbedtls_snprintf( buf, buflen, "X509 - Destination buffer is too small" );
#endif /* MBEDTLS_X509_USE_C || MBEDTLS_X509_CREATE_C */
        // END generated code

        if( strlen( buf ) == 0 )
            mbedtls_snprintf( buf, buflen, "UNKNOWN ERROR CODE (%04X)", use_ret );
    }

    use_ret = ret & ~0xFF80;

    if( use_ret == 0 )
        return;

    // If high level code is present, make a concatenation between both
    // error strings.
    //
    len = strlen( buf );

    if( len > 0 )
    {
        if( buflen - len < 5 )
            return;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -480,6 +480,8 @@
             mbedtls_snprintf( buf, buflen, "X509 - Read/write of file failed" );
         if( use_ret == -(MBEDTLS_ERR_X509_BUFFER_TOO_SMALL) )
             mbedtls_snprintf( buf, buflen, "X509 - Destination buffer is too small" );
+        if( use_ret == -(MBEDTLS_ERR_X509_FATAL_ERROR) )
+            mbedtls_snprintf( buf, buflen, "X509 - A fatal error occured, eg the chain is too long or the vrfy callback failed" );
 #endif /* MBEDTLS_X509_USE_C || MBEDTLS_X509_CREATE_C */
         // END generated code
 
```
