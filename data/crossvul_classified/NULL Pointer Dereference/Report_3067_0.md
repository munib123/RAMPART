# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 3067_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3067_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 2241-2281 of the vulnerable file.

#else
    SSLerr(SSL_F_TLS_CONSTRUCT_CKE_RSA, ERR_R_INTERNAL_ERROR);
    *al = SSL_AD_INTERNAL_ERROR;
    return 0;
#endif
}

static int tls_construct_cke_dhe(SSL *s, unsigned char **p, int *len, int *al)
{
#ifndef OPENSSL_NO_DH
    DH *dh_clnt = NULL;
    const BIGNUM *pub_key;
    EVP_PKEY *ckey = NULL, *skey = NULL;

    skey = s->s3->peer_tmp;
    if (skey == NULL) {
        SSLerr(SSL_F_TLS_CONSTRUCT_CKE_DHE, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    ckey = ssl_generate_pkey(skey);
    dh_clnt = EVP_PKEY_get0_DH(ckey);

    if (dh_clnt == NULL || ssl_derive(s, ckey, skey) == 0) {
        SSLerr(SSL_F_TLS_CONSTRUCT_CKE_DHE, ERR_R_INTERNAL_ERROR);
        EVP_PKEY_free(ckey);
        return 0;
    }

    /* send off the data */
    DH_get0_key(dh_clnt, &pub_key, NULL);
    *len = BN_num_bytes(pub_key);
    s2n(*len, *p);
    BN_bn2bin(pub_key, *p);
    *len += 2;
    EVP_PKEY_free(ckey);

    return 1;
#else
    SSLerr(SSL_F_TLS_CONSTRUCT_CKE_DHE, ERR_R_INTERNAL_ERROR);
    *al = SSL_AD_INTERNAL_ERROR;
    return 0;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2258,6 +2258,11 @@
         return 0;
     }
     ckey = ssl_generate_pkey(skey);
+    if (ckey == NULL) {
+        SSLerr(SSL_F_TLS_CONSTRUCT_CKE_DHE, ERR_R_INTERNAL_ERROR);
+        return 0;
+    }
+
     dh_clnt = EVP_PKEY_get0_DH(ckey);
 
     if (dh_clnt == NULL || ssl_derive(s, ckey, skey) == 0) {
@@ -2296,6 +2301,10 @@
     }
 
     ckey = ssl_generate_pkey(skey);
+    if (ckey == NULL) {
+        SSLerr(SSL_F_TLS_CONSTRUCT_CKE_ECDHE, ERR_R_INTERNAL_ERROR);
+        goto err;
+    }
 
     if (ssl_derive(s, ckey, skey) == 0) {
         SSLerr(SSL_F_TLS_CONSTRUCT_CKE_ECDHE, ERR_R_EVP_LIB);
```
