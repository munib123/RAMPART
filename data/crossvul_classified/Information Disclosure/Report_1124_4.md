# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 1124_4
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1124_4`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 53-95 of the vulnerable file.

    size_t n_size = ( grp->nbits + 7 ) / 8;
    size_t use_size = blen > n_size ? n_size : blen;

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( x, buf, use_size ) );
    if( use_size * 8 > grp->nbits )
        MBEDTLS_MPI_CHK( mbedtls_mpi_shift_r( x, use_size * 8 - grp->nbits ) );

    /* While at it, reduce modulo N */
    if( mbedtls_mpi_cmp_mpi( x, &grp->N ) >= 0 )
        MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mpi( x, x, &grp->N ) );

cleanup:
    return( ret );
}

#if !defined(MBEDTLS_ECDSA_SIGN_ALT)
/*
 * Compute ECDSA signature of a hashed message (SEC1 4.1.3)
 * Obviously, compared to SEC1 4.1.3, we skip step 4 (hash message)
 */
int mbedtls_ecdsa_sign( mbedtls_ecp_group *grp, mbedtls_mpi *r, mbedtls_mpi *s,
                const mbedtls_mpi *d, const unsigned char *buf, size_t blen,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    int ret, key_tries, sign_tries, blind_tries;
    mbedtls_ecp_point R;
    mbedtls_mpi k, e, t;

    /* Fail cleanly on curves such as Curve25519 that can't be used for ECDSA */
    if( grp->N.p == NULL )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    /* Make sure d is in range 1..n-1 */
    if( mbedtls_mpi_cmp_int( d, 1 ) < 0 || mbedtls_mpi_cmp_mpi( d, &grp->N ) >= 0 )
        return( MBEDTLS_ERR_ECP_INVALID_KEY );

    mbedtls_ecp_point_init( &R );
    mbedtls_mpi_init( &k ); mbedtls_mpi_init( &e ); mbedtls_mpi_init( &t );

    sign_tries = 0;
    do
    {
        /*
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -70,9 +70,14 @@
  * Compute ECDSA signature of a hashed message (SEC1 4.1.3)
  * Obviously, compared to SEC1 4.1.3, we skip step 4 (hash message)
  */
-int mbedtls_ecdsa_sign( mbedtls_ecp_group *grp, mbedtls_mpi *r, mbedtls_mpi *s,
-                const mbedtls_mpi *d, const unsigned char *buf, size_t blen,
-                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
+static int ecdsa_sign_internal( mbedtls_ecp_group *grp, mbedtls_mpi *r,
+                                mbedtls_mpi *s, const mbedtls_mpi *d,
+                                const unsigned char *buf, size_t blen,
+                                int (*f_rng)(void *, unsigned char *, size_t),
+                                void *p_rng,
+                                int (*f_rng_blind)(void *, unsigned char *,
+                                                   size_t),
+                                void *p_rng_blind )
 {
     int ret, key_tries, sign_tries, blind_tries;
     mbedtls_ecp_point R;
@@ -99,7 +104,10 @@
         key_tries = 0;
         do
         {
-            MBEDTLS_MPI_CHK( mbedtls_ecp_gen_keypair( grp, &k, &R, f_rng, p_rng ) );
+            MBEDTLS_MPI_CHK( mbedtls_ecp_gen_privkey( grp, &k, f_rng, p_rng ) );
+
+            MBEDTLS_MPI_CHK( mbedtls_ecp_mul( grp, &R, &k, &grp->G,
+                                              f_rng_blind, p_rng_blind ) );
             MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( r, &R.X, &grp->N ) );
 
             if( key_tries++ > 10 )
@@ -118,15 +126,20 @@
         /*
          * Generate a random value to blind inv_mod in next step,
          * avoiding a potential timing leak.
+         *
+         * This loop does the same job as mbedtls_ecp_gen_privkey() and it is
+         * replaced by a call to it in the mainline. This change is not
+         * necessary to backport the fix separating the blinding and ephemeral
+         * key generating RNGs, therefore the original code is kept.
          */
         blind_tries = 0;
         do
         {
             size_t n_size = ( grp->nbits + 7 ) / 8;
-            MBEDTLS_MPI_CHK( mbedtls_mpi_fill_random( &t, n_size, f_rng, p_rng ) );
+            MBEDTLS_MPI_CHK( mbedtls_mpi_fill_random( &t, n_size, f_rng_blind,
+                                                      p_rng_blind ) );
             MBEDTLS_MPI_CHK( mbedtls_mpi_shift_r( &t, 8 * n_size - grp->nbits ) );
 
-            /* See mbedtls_ecp_gen_keypair() */
             if( ++blind_tries > 30 )
                 return( MBEDTLS_ERR_ECP_RANDOM_FAILED );
         }
@@ -158,15 +171,27 @@
 
     return( ret );
 }
+
+int mbedtls_ecdsa_sign( mbedtls_ecp_group *grp, mbedtls_mpi *r, mbedtls_mpi *s,
+                        const mbedtls_mpi *d, const unsigned char *buf,
+                        size_t blen,
+                        int (*f_rng)(void *, unsigned char *, size_t),
+                        void *p_rng )
+{
+    /* Use the same RNG for both blinding and ephemeral key generation */
+    return( ecdsa_sign_internal( grp, r, s, d, buf, blen, f_rng, p_rng,
+                                 f_rng, p_rng ) );
+}
 #endif /* MBEDTLS_ECDSA_SIGN_ALT */
 
 #if defined(MBEDTLS_ECDSA_DETERMINISTIC)
-/*
- * Deterministic signature wrapper
- */
-int mbedtls_ecdsa_sign_det( mbedtls_ecp_group *grp, mbedtls_mpi *r, mbedtls_mpi *s,
-                    const mbedtls_mpi *d, const unsigned char *buf, size_t blen,
-                    mbedtls_md_type_t md_alg )
+static int ecdsa_sign_det_internal( mbedtls_ecp_group *grp, mbedtls_mpi *r,
+                                    mbedtls_mpi *s, const mbedtls_mpi *d,
+                                    const unsigned char *buf, size_t blen,
+                                    mbedtls_md_type_t md_alg,
+                                    int (*f_rng_blind)(void *, unsigned char *,
+                                                       size_t),
+                                    void *p_rng_blind )
 {
     int ret;
     mbedtls_hmac_drbg_context rng_ctx;
@@ -174,12 +199,16 @@
     size_t grp_len = ( grp->nbits + 7 ) / 8;
     const mbedtls_md_info_t *md_info;
     mbedtls_mpi h;
+    /* Variables for deterministic blinding fallback */
+    const char* blind_label = "BLINDING CONTEXT";
+    mbedtls_hmac_drbg_context rng_ctx_blind;
 
     if( ( md_info = mbedtls_md_info_from_type( md_alg ) ) == NULL )
         return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
 
     mbedtls_mpi_init( &h );
     mbedtls_hmac_drbg_init( &rng_ctx );
+    mbedtls_hmac_drbg_init( &rng_ctx_blind );
 
     /* Use private key and message hash (reduced) to initialize HMAC_DRBG */
     MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( d, data, grp_len ) );
@@ -187,14 +216,70 @@
     MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &h, data + grp_len, grp_len ) );
     mbedtls_hmac_drbg_seed_buf( &rng_ctx, md_info, data, 2 * grp_len );
 
-    ret = mbedtls_ecdsa_sign( grp, r, s, d, buf, blen,
-                      mbedtls_hmac_drbg_random, &rng_ctx );
+    if( f_rng_blind != NULL )
+        ret = ecdsa_sign_internal( grp, r, s, d, buf, blen,
+                                   mbedtls_hmac_drbg_random, &rng_ctx,
+                                   f_rng_blind, p_rng_blind );
+    else
+    {
+        /*
+         * To avoid reusing rng_ctx and risking incorrect behavior we seed a
+         * second HMAC-DRBG with the same seed. We also apply a label to avoid
+         * reusing the bits of the ephemeral key for blinding and eliminate the
+         * risk that they leak this way.
+         */
+
+        mbedtls_hmac_drbg_seed_buf( &rng_ctx_blind, md_info,
+                                    data, 2 * grp_len );
+        ret = mbedtls_hmac_drbg_update_ret( &rng_ctx_blind,
+                                            (const unsigned char*) blind_label,
+                                            strlen( blind_label ) );
+        if( ret != 0 )
+            goto cleanup;
+
+        /*
+         * Since the output of the RNGs is always the same for the same key and
+         * message, this limits the efficiency of blinding and leaks information
+         * through side channels. After mbedtls_ecdsa_sign_det() is removed NULL
+         * won't be a valid value for f_rng_blind anymore. Therefore it should
+         * be checked by the caller and this branch and check can be removed.
+         */
+        ret = ecdsa_sign_internal( grp, r, s, d, buf, blen,
+                                   mbedtls_hmac_drbg_random, &rng_ctx,
+                                   mbedtls_hmac_drbg_random, &rng_ctx_blind );
+
+    }
 
 cleanup:
     mbedtls_hmac_drbg_free( &rng_ctx );
+    mbedtls_hmac_drbg_free( &rng_ctx_blind );
     mbedtls_mpi_free( &h );
 
     return( ret );
+}
+
+/*
+ * Deterministic signature wrappers
+ */
+int mbedtls_ecdsa_sign_det( mbedtls_ecp_group *grp, mbedtls_mpi *r,
+                            mbedtls_mpi *s, const mbedtls_mpi *d,
+                            const unsigned char *buf, size_t blen,
+                            mbedtls_md_type_t md_alg )
+{
+    return( ecdsa_sign_det_internal( grp, r, s, d, buf, blen, md_alg,
+                                     NULL, NULL ) );
+}
+
+int mbedtls_ecdsa_sign_det_ext( mbedtls_ecp_group *grp, mbedtls_mpi *r,
+                                mbedtls_mpi *s, const mbedtls_mpi *d,
+                                const unsigned char *buf, size_t blen,
+                                mbedtls_md_type_t md_alg,
+                                int (*f_rng_blind)(void *, unsigned char *,
+                                                   size_t),
+                                void *p_rng_blind )
+{
+    return( ecdsa_sign_det_internal( grp, r, s, d, buf, blen, md_alg,
+                                     f_rng_blind, p_rng_blind ) );
 }
 #endif /* MBEDTLS_ECDSA_DETERMINISTIC */
 
@@ -326,17 +411,15 @@
     mbedtls_mpi_init( &s );
 
 #if defined(MBEDTLS_ECDSA_DETERMINISTIC)
-    (void) f_rng;
-    (void) p_rng;
-
... (diff truncated)
```
