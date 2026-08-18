# CrossVul Fix Pair: Improper Authentication in c
**Pair ID:** 2757_1
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2757_1`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```c
Lines 2185-2225 of the vulnerable file.


/*
 * Verify the certificate validity, with profile
 */
int mbedtls_x509_crt_verify_with_profile( mbedtls_x509_crt *crt,
                     mbedtls_x509_crt *trust_ca,
                     mbedtls_x509_crl *ca_crl,
                     const mbedtls_x509_crt_profile *profile,
                     const char *cn, uint32_t *flags,
                     int (*f_vrfy)(void *, mbedtls_x509_crt *, int, uint32_t *),
                     void *p_vrfy )
{
    size_t cn_len;
    int ret;
    int pathlen = 0, selfsigned = 0;
    mbedtls_x509_crt *parent;
    mbedtls_x509_name *name;
    mbedtls_x509_sequence *cur = NULL;
    mbedtls_pk_type_t pk_type;

    if( profile == NULL )
        return( MBEDTLS_ERR_X509_BAD_INPUT_DATA );

    *flags = 0;

    if( cn != NULL )
    {
        name = &crt->subject;
        cn_len = strlen( cn );

        if( crt->ext_types & MBEDTLS_X509_EXT_SUBJECT_ALT_NAME )
        {
            cur = &crt->subject_alt_names;

            while( cur != NULL )
            {
                if( cur->buf.len == cn_len &&
                    x509_memcasecmp( cn, cur->buf.p, cn_len ) == 0 )
                    break;

                if( cur->buf.len > 2 &&
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2202,10 +2202,13 @@
     mbedtls_x509_sequence *cur = NULL;
     mbedtls_pk_type_t pk_type;
 
+    *flags = 0;
+
     if( profile == NULL )
-        return( MBEDTLS_ERR_X509_BAD_INPUT_DATA );
-
-    *flags = 0;
+    {
+        ret = MBEDTLS_ERR_X509_BAD_INPUT_DATA;
+        goto exit;
+    }
 
     if( cn != NULL )
     {
@@ -2280,7 +2283,7 @@
         ret = x509_crt_verify_top( crt, parent, ca_crl, profile,
                                    pathlen, selfsigned, flags, f_vrfy, p_vrfy );
         if( ret != 0 )
-            return( ret );
+            goto exit;
     }
     else
     {
@@ -2295,15 +2298,22 @@
             ret = x509_crt_verify_child( crt, parent, trust_ca, ca_crl, profile,
                                          pathlen, selfsigned, flags, f_vrfy, p_vrfy );
             if( ret != 0 )
-                return( ret );
+                goto exit;
         }
         else
         {
             ret = x509_crt_verify_top( crt, trust_ca, ca_crl, profile,
                                        pathlen, selfsigned, flags, f_vrfy, p_vrfy );
             if( ret != 0 )
-                return( ret );
-        }
+                goto exit;
+        }
+    }
+
+exit:
+    if( ret != 0 )
+    {
+        *flags = (uint32_t) -1;
+        return( ret );
     }
 
     if( *flags != 0 )
```
