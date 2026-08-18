# CrossVul Fix Pair: Inadequate Encryption Strength in c
**Pair ID:** 3970_2
**Vulnerability Class:** Inadequate Encryption Strength
**CWE:** CWE-326
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3970_2`)

## Vulnerability Information & PoC

## Description
Inadequate Encryption Strength - A weak encryption scheme can be subjected to brute force attacks that have a reasonable chance of succeeding using current attack methods and resources.

## Vulnerable Code
```c
Lines 422-462 of the vulnerable file.


/* ECC predefined curve sets  */
extern const ecc_set_type ecc_sets[];

WOLFSSL_API
const char* wc_ecc_get_name(int curve_id);

#ifndef WOLFSSL_ATECC508A

#ifdef WOLFSSL_PUBLIC_ECC_ADD_DBL
    #define ECC_API    WOLFSSL_API
#else
    #define ECC_API    WOLFSSL_LOCAL
#endif

ECC_API int ecc_mul2add(ecc_point* A, mp_int* kA,
                ecc_point* B, mp_int* kB,
                ecc_point* C, mp_int* a, mp_int* modulus, void* heap);

ECC_API int ecc_map(ecc_point*, mp_int*, mp_digit);
ECC_API int ecc_projective_add_point(ecc_point* P, ecc_point* Q, ecc_point* R,
                                     mp_int* a, mp_int* modulus, mp_digit mp);
ECC_API int ecc_projective_dbl_point(ecc_point* P, ecc_point* R, mp_int* a,
                                     mp_int* modulus, mp_digit mp);

#endif

WOLFSSL_API
int wc_ecc_make_key(WC_RNG* rng, int keysize, ecc_key* key);
WOLFSSL_ABI WOLFSSL_API
int wc_ecc_make_key_ex(WC_RNG* rng, int keysize, ecc_key* key, int curve_id);
WOLFSSL_API
int wc_ecc_make_pub(ecc_key* key, ecc_point* pubOut);
WOLFSSL_API
int wc_ecc_check_key(ecc_key* key);
WOLFSSL_API
int wc_ecc_is_point(ecc_point* ecp, mp_int* a, mp_int* b, mp_int* prime);

#ifdef HAVE_ECC_DHE
WOLFSSL_API
int wc_ecc_shared_secret(ecc_key* private_key, ecc_key* public_key, byte* out,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -439,6 +439,7 @@
                 ecc_point* C, mp_int* a, mp_int* modulus, void* heap);
 
 ECC_API int ecc_map(ecc_point*, mp_int*, mp_digit);
+ECC_API int ecc_map_ex(ecc_point*, mp_int*, mp_digit, int ct);
 ECC_API int ecc_projective_add_point(ecc_point* P, ecc_point* Q, ecc_point* R,
                                      mp_int* a, mp_int* modulus, mp_digit mp);
 ECC_API int ecc_projective_dbl_point(ecc_point* P, ecc_point* R, mp_int* a,
```
