# CrossVul Fix Pair: Improper Authentication in c
**Pair ID:** 2756_6
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2756_6`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```c
Lines 2040-2081 of the vulnerable file.

                mbedtls_x509_crt *child, mbedtls_x509_crt *parent,
                mbedtls_x509_crt *trust_ca, mbedtls_x509_crl *ca_crl,
                const mbedtls_x509_crt_profile *profile,
                int path_cnt, int self_cnt, uint32_t *flags,
                int (*f_vrfy)(void *, mbedtls_x509_crt *, int, uint32_t *),
                void *p_vrfy )
{
    int ret;
    uint32_t parent_flags = 0;
    unsigned char hash[MBEDTLS_MD_MAX_SIZE];
    mbedtls_x509_crt *grandparent;
    const mbedtls_md_info_t *md_info;

    /* Counting intermediate self signed certificates */
    if( ( path_cnt != 0 ) && x509_name_cmp( &child->issuer, &child->subject ) == 0 )
        self_cnt++;

    /* path_cnt is 0 for the first intermediate CA */
    if( 1 + path_cnt > MBEDTLS_X509_MAX_INTERMEDIATE_CA )
    {
        *flags |= MBEDTLS_X509_BADCERT_NOT_TRUSTED;
        return( MBEDTLS_ERR_X509_CERT_VERIFY_FAILED );
    }

    if( mbedtls_x509_time_is_past( &child->valid_to ) )
        *flags |= MBEDTLS_X509_BADCERT_EXPIRED;

    if( mbedtls_x509_time_is_future( &child->valid_from ) )
        *flags |= MBEDTLS_X509_BADCERT_FUTURE;

    if( x509_profile_check_md_alg( profile, child->sig_md ) != 0 )
        *flags |= MBEDTLS_X509_BADCERT_BAD_MD;

    if( x509_profile_check_pk_alg( profile, child->sig_pk ) != 0 )
        *flags |= MBEDTLS_X509_BADCERT_BAD_PK;

    md_info = mbedtls_md_info_from_type( child->sig_md );
    if( md_info == NULL )
    {
        /*
         * Cannot check 'unknown' hash
         */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2057,8 +2057,8 @@
     /* path_cnt is 0 for the first intermediate CA */
     if( 1 + path_cnt > MBEDTLS_X509_MAX_INTERMEDIATE_CA )
     {
-        *flags |= MBEDTLS_X509_BADCERT_NOT_TRUSTED;
-        return( MBEDTLS_ERR_X509_CERT_VERIFY_FAILED );
+        /* return immediately as the goal is to avoid unbounded recursion */
+        return( MBEDTLS_ERR_X509_FATAL_ERROR );
     }
 
     if( mbedtls_x509_time_is_past( &child->valid_to ) )
@@ -2310,6 +2310,10 @@
     }
 
 exit:
+    /* prevent misuse of the vrfy callback */
+    if( ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED )
+        ret = MBEDTLS_ERR_X509_FATAL_ERROR;
+
     if( ret != 0 )
     {
         *flags = (uint32_t) -1;
```
