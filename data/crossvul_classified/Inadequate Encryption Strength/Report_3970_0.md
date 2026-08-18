# CrossVul Fix Pair: Inadequate Encryption Strength in c
**Pair ID:** 3970_0
**Vulnerability Class:** Inadequate Encryption Strength
**CWE:** CWE-326
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3970_0`)

## Vulnerability Information & PoC

## Description
Inadequate Encryption Strength - A weak encryption scheme can be subjected to brute force attacks that have a reasonable chance of succeeding using current attack methods and resources.

## Vulnerable Code
```c
Lines 2268-2308 of the vulnerable file.

#ifndef WOLFSSL_SP_NO_256
    if (mp_count_bits(modulus) == 256) {
        return sp_ecc_proj_dbl_point_256(P->x, P->y, P->z, R->x, R->y, R->z);
    }
#endif
#ifdef WOLFSSL_SP_384
    if (mp_count_bits(modulus) == 384) {
        return sp_ecc_proj_dbl_point_384(P->x, P->y, P->z, R->x, R->y, R->z);
    }
#endif
    return ECC_BAD_ARG_E;
#endif
}


/**
  Map a projective Jacobian point back to affine space
  P        [in/out] The point to map
  modulus  The modulus of the field the ECC curve is in
  mp       The "b" value from montgomery_setup()
  return   MP_OKAY on success
*/
int ecc_map(ecc_point* P, mp_int* modulus, mp_digit mp)
{
#ifndef WOLFSSL_SP_MATH
#ifdef WOLFSSL_SMALL_STACK
   mp_int* t1 = NULL;
   mp_int* t2 = NULL;
#ifdef ALT_ECC_SIZE
   mp_int* rx = NULL;
   mp_int* ry = NULL;
   mp_int* rz = NULL;
#endif
#else
   mp_int  t1[1], t2[1];
#ifdef ALT_ECC_SIZE
   mp_int  rx[1], ry[1], rz[1];
#endif
#endif /* WOLFSSL_SMALL_STACK */
   mp_int *x, *y, *z;
   int    err;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2285,9 +2285,10 @@
   P        [in/out] The point to map
   modulus  The modulus of the field the ECC curve is in
   mp       The "b" value from montgomery_setup()
+  ct       Operation should be constant time.
   return   MP_OKAY on success
 */
-int ecc_map(ecc_point* P, mp_int* modulus, mp_digit mp)
+int ecc_map_ex(ecc_point* P, mp_int* modulus, mp_digit mp, int ct)
 {
 #ifndef WOLFSSL_SP_MATH
 #ifdef WOLFSSL_SMALL_STACK
@@ -2306,6 +2307,8 @@
 #endif /* WOLFSSL_SMALL_STACK */
    mp_int *x, *y, *z;
    int    err;
+
+   (void)ct;
 
    if (P == NULL || modulus == NULL)
        return ECC_BAD_ARG_E;
@@ -2402,12 +2405,23 @@
    z = P->z;
 #endif
 
-   /* first map z back to normal */
-   err = mp_montgomery_reduce(z, modulus, mp);
-
    /* get 1/z */
-   if (err == MP_OKAY)
-       err = mp_invmod(z, modulus, t1);
+   if (err == MP_OKAY) {
+#if defined(ECC_TIMING_RESISTANT) && defined(USE_FAST_MATH)
+       if (ct) {
+           err = mp_invmod_mont_ct(z, modulus, t1, mp);
+           if (err == MP_OKAY)
+               err = mp_montgomery_reduce(t1, modulus, mp);
+       }
+       else
+#endif
+       {
+           /* first map z back to normal */
+           err = mp_montgomery_reduce(z, modulus, mp);
+           if (err == MP_OKAY)
+               err = mp_invmod(z, modulus, t1);
+       }
+   }
 
    /* get 1/z^2 and 1/z^3 */
    if (err == MP_OKAY)
@@ -2484,6 +2498,10 @@
 #endif
 }
 
+int ecc_map(ecc_point* P, mp_int* modulus, mp_digit mp)
+{
+    return ecc_map_ex(P, modulus, mp, 0);
+}
 #endif /* !WOLFSSL_SP_MATH || WOLFSSL_PUBLIC_ECC_ADD_DBL */
 
 #if !defined(FREESCALE_LTC_ECC) && !defined(WOLFSSL_STM32_PKA)
@@ -3639,6 +3657,8 @@
     }
 #else
     {
+        mp_digit mp = 0;
+
         /* make new point */
         result = wc_ecc_new_point_h(private_key->heap);
         if (result == NULL) {
@@ -3649,8 +3669,16 @@
             return MEMORY_E;
         }
 
-        err = wc_ecc_mulmod_ex(k, point, result, curve->Af, curve->prime, 1,
+        /* Map in a separate call as this should be constant time */
+        err = wc_ecc_mulmod_ex(k, point, result, curve->Af, curve->prime, 0,
                                                              private_key->heap);
+        if (err == MP_OKAY) {
+            err = mp_montgomery_setup(curve->prime, &mp);
+        }
+        if (err == MP_OKAY) {
+            /* Use constant time map if compiled in */
+            err = ecc_map_ex(result, curve->prime, mp, 1);
+        }
         if (err == MP_OKAY) {
             x = mp_unsigned_bin_size(curve->prime);
             if (*outlen < x || (int)x < mp_unsigned_bin_size(result->x)) {
@@ -4008,6 +4036,8 @@
         err = WC_KEY_SIZE_E;
 #else
     {
+        mp_digit mp;
+
         if (err == MP_OKAY) {
             base = wc_ecc_new_point_h(key->heap);
             if (base == NULL)
@@ -4023,11 +4053,19 @@
 
         /* make the public key */
         if (err == MP_OKAY) {
+            /* Map in a separate call as this should be constant time */
             err = wc_ecc_mulmod_ex(&key->k, base, pub, curve->Af, curve->prime,
-                                                                  1, key->heap);
+                                                                  0, key->heap);
             if (err == MP_MEM) {
                err = MEMORY_E;
             }
+        }
+        if (err == MP_OKAY) {
+            err = mp_montgomery_setup(curve->prime, &mp);
+        }
+        if (err == MP_OKAY) {
+            /* Use constant time map if compiled in */
+            err = ecc_map_ex(pub, curve->prime, mp, 1);
         }
 
         wc_ecc_del_point_h(base, key->heap);
```
