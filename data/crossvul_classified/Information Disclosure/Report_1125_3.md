# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 1125_3
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1125_3`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 237-277 of the vulnerable file.

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
static int ecdsa_sign_restartable( mbedtls_ecp_group *grp,
                mbedtls_mpi *r, mbedtls_mpi *s,
                const mbedtls_mpi *d, const unsigned char *buf, size_t blen,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
                mbedtls_ecdsa_restart_ctx *rs_ctx )
{
    int ret, key_tries, sign_tries;
    int *p_sign_tries = &sign_tries, *p_key_tries = &key_tries;
    mbedtls_ecp_point R;
    mbedtls_mpi k, e, t;
    mbedtls_mpi *pk = &k, *pr = r;

    /* Fail cleanly on curves such as Curve25519 that can't be used for ECDSA */
    if( grp->N.p == NULL )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    /* Make sure d is in range 1..n-1 */
    if( mbedtls_mpi_cmp_int( d, 1 ) < 0 || mbedtls_mpi_cmp_mpi( d, &grp->N ) >= 0 )
        return( MBEDTLS_ERR_ECP_INVALID_KEY );

    mbedtls_ecp_point_init( &R );
    mbedtls_mpi_init( &k ); mbedtls_mpi_init( &e ); mbedtls_mpi_init( &t );

    ECDSA_RS_ENTER( sig );

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -254,6 +254,8 @@
                 mbedtls_mpi *r, mbedtls_mpi *s,
                 const mbedtls_mpi *d, const unsigned char *buf, size_t blen,
                 int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
+                int (*f_rng_blind)(void *, unsigned char *, size_t),
+                void *p_rng_blind,
                 mbedtls_ecdsa_restart_ctx *rs_ctx )
 {
     int ret, key_tries, sign_tries;
@@ -323,7 +325,9 @@
 mul:
 #endif
             MBEDTLS_MPI_CHK( mbedtls_ecp_mul_restartable( grp, &R, pk, &grp->G,
-                                                  f_rng, p_rng, ECDSA_RS_ECP ) );
+                                                          f_rng_blind,
+                                                          p_rng_blind,
+                                                          ECDSA_RS_ECP ) );
             MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( pr, &R.X, &grp->N ) );
         }
         while( mbedtls_mpi_cmp_int( pr, 0 ) == 0 );
@@ -349,7 +353,8 @@
          * Generate a random value to blind inv_mod in next step,
          * avoiding a potential timing leak.
          */
-        MBEDTLS_MPI_CHK( mbedtls_ecp_gen_privkey( grp, &t, f_rng, p_rng ) );
+        MBEDTLS_MPI_CHK( mbedtls_ecp_gen_privkey( grp, &t, f_rng_blind,
+                                                  p_rng_blind ) );
 
         /*
          * Step 6: compute s = (e + r * d) / k = t (e + rd) / (kt) mod n
@@ -392,8 +397,9 @@
     ECDSA_VALIDATE_RET( f_rng != NULL );
     ECDSA_VALIDATE_RET( buf   != NULL || blen == 0 );
 
+    /* Use the same RNG for both blinding and ephemeral key generation */
     return( ecdsa_sign_restartable( grp, r, s, d, buf, blen,
-                                    f_rng, p_rng, NULL ) );
+                                    f_rng, p_rng, f_rng, p_rng, NULL ) );
 }
 #endif /* !MBEDTLS_ECDSA_SIGN_ALT */
 
@@ -405,6 +411,8 @@
                     mbedtls_mpi *r, mbedtls_mpi *s,
                     const mbedtls_mpi *d, const unsigned char *buf, size_t blen,
                     mbedtls_md_type_t md_alg,
+                    int (*f_rng_blind)(void *, unsigned char *, size_t),
+                    void *p_rng_blind,
                     mbedtls_ecdsa_restart_ctx *rs_ctx )
 {
     int ret;
@@ -451,8 +459,70 @@
     ret = mbedtls_ecdsa_sign( grp, r, s, d, buf, blen,
                               mbedtls_hmac_drbg_random, p_rng );
 #else
-    ret = ecdsa_sign_restartable( grp, r, s, d, buf, blen,
-                      mbedtls_hmac_drbg_random, p_rng, rs_ctx );
+    if( f_rng_blind != NULL )
+        ret = ecdsa_sign_restartable( grp, r, s, d, buf, blen,
+                                      mbedtls_hmac_drbg_random, p_rng,
+                                      f_rng_blind, p_rng_blind, rs_ctx );
+    else
+    {
+        mbedtls_hmac_drbg_context *p_rng_blind_det;
+
+#if !defined(MBEDTLS_ECP_RESTARTABLE)
+        /*
+         * To avoid reusing rng_ctx and risking incorrect behavior we seed a
+         * second HMAC-DRBG with the same seed. We also apply a label to avoid
+         * reusing the bits of the ephemeral key for blinding and eliminate the
+         * risk that they leak this way.
+         */
+        const char* blind_label = "BLINDING CONTEXT";
+        mbedtls_hmac_drbg_context rng_ctx_blind;
+
+        mbedtls_hmac_drbg_init( &rng_ctx_blind );
+        p_rng_blind_det = &rng_ctx_blind;
+
+        mbedtls_hmac_drbg_seed_buf( p_rng_blind_det, md_info,
+                                    data, 2 * grp_len );
+        ret = mbedtls_hmac_drbg_update_ret( p_rng_blind_det,
+                                            (const unsigned char*) blind_label,
+                                            strlen( blind_label ) );
+        if( ret != 0 )
+        {
+            mbedtls_hmac_drbg_free( &rng_ctx_blind );
+            goto cleanup;
+        }
+#else
+        /*
+         * In the case of restartable computations we would either need to store
+         * the second RNG in the restart context too or set it up at every
+         * restart. The first option would penalize the correct application of
+         * the function and the second would defeat the purpose of the
+         * restartable feature.
+         *
+         * Therefore in this case we reuse the original RNG. This comes with the
+         * price that the resulting signature might not be a valid deterministic
+         * ECDSA signature with a very low probability (same magnitude as
+         * successfully guessing the private key). However even then it is still
+         * a valid ECDSA signature.
+         */
+        p_rng_blind_det = p_rng;
+#endif /* MBEDTLS_ECP_RESTARTABLE */
+
+        /*
+         * Since the output of the RNGs is always the same for the same key and
+         * message, this limits the efficiency of blinding and leaks information
+         * through side channels. After mbedtls_ecdsa_sign_det() is removed NULL
+         * won't be a valid value for f_rng_blind anymore. Therefore it should
+         * be checked by the caller and this branch and check can be removed.
+         */
+        ret = ecdsa_sign_restartable( grp, r, s, d, buf, blen,
+                                      mbedtls_hmac_drbg_random, p_rng,
+                                      mbedtls_hmac_drbg_random, p_rng_blind_det,
+                                      rs_ctx );
+
+#if !defined(MBEDTLS_ECP_RESTARTABLE)
+        mbedtls_hmac_drbg_free( &rng_ctx_blind );
+#endif
+    }
 #endif /* MBEDTLS_ECDSA_SIGN_ALT */
 
 cleanup:
@@ -465,11 +535,12 @@
 }
 
 /*
- * Deterministic signature wrapper
- */
-int mbedtls_ecdsa_sign_det( mbedtls_ecp_group *grp, mbedtls_mpi *r, mbedtls_mpi *s,
-                    const mbedtls_mpi *d, const unsigned char *buf, size_t blen,
-                    mbedtls_md_type_t md_alg )
+ * Deterministic signature wrappers
+ */
+int mbedtls_ecdsa_sign_det( mbedtls_ecp_group *grp, mbedtls_mpi *r,
+                            mbedtls_mpi *s, const mbedtls_mpi *d,
+                            const unsigned char *buf, size_t blen,
+                            mbedtls_md_type_t md_alg )
 {
     ECDSA_VALIDATE_RET( grp   != NULL );
     ECDSA_VALIDATE_RET( r     != NULL );
@@ -477,7 +548,27 @@
     ECDSA_VALIDATE_RET( d     != NULL );
     ECDSA_VALIDATE_RET( buf   != NULL || blen == 0 );
 
-    return( ecdsa_sign_det_restartable( grp, r, s, d, buf, blen, md_alg, NULL ) );
+    return( ecdsa_sign_det_restartable( grp, r, s, d, buf, blen, md_alg,
+                                        NULL, NULL, NULL ) );
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
+    ECDSA_VALIDATE_RET( grp   != NULL );
+    ECDSA_VALIDATE_RET( r     != NULL );
+    ECDSA_VALIDATE_RET( s     != NULL );
+    ECDSA_VALIDATE_RET( d     != NULL );
+    ECDSA_VALIDATE_RET( buf   != NULL || blen == 0 );
+    ECDSA_VALIDATE_RET( f_rng_blind != NULL );
+
+    return( ecdsa_sign_det_restartable( grp, r, s, d, buf, blen, md_alg,
+                                        f_rng_blind, p_rng_blind, NULL ) );
 }
 #endif /* MBEDTLS_ECDSA_DETERMINISTIC */
 
@@ -656,11 +747,9 @@
     mbedtls_mpi_init( &s );
 
 #if defined(MBEDTLS_ECDSA_DETERMINISTIC)
-    (void) f_rng;
-    (void) p_rng;
-
     MBEDTLS_MPI_CHK( ecdsa_sign_det_restartable( &ctx->grp, &r, &s, &ctx->d,
-                             hash, hlen, md_alg, rs_ctx ) );
+                                                 hash, hlen, md_alg, f_rng,
+                                                 p_rng, rs_ctx ) );
 #else
     (void) md_alg;
 
@@ -668,8 +757,10 @@
... (diff truncated)
```
