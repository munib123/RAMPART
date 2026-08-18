# CrossVul Fix Pair: Inadequate Encryption Strength in c
**Pair ID:** 3970_3
**Vulnerability Class:** Inadequate Encryption Strength
**CWE:** CWE-326
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3970_3`)

## Vulnerability Information & PoC

## Description
Inadequate Encryption Strength - A weak encryption scheme can be subjected to brute force attacks that have a reasonable chance of succeeding using current attack methods and resources.

## Vulnerable Code
```c
Lines 518-558 of the vulnerable file.

/* d = a + b (mod c) */
/*int fp_addmod(fp_int *a, fp_int *b, fp_int *c, fp_int *d);*/

/* d = a - b (mod c) */
/*int fp_submod(fp_int *a, fp_int *b, fp_int *c, fp_int *d);*/

/* d = a * b (mod c) */
int fp_mulmod(fp_int *a, fp_int *b, fp_int *c, fp_int *d);

/* d = a - b (mod c) */
int fp_submod(fp_int *a, fp_int *b, fp_int *c, fp_int *d);

/* d = a + b (mod c) */
int fp_addmod(fp_int *a, fp_int *b, fp_int *c, fp_int *d);

/* c = a * a (mod b) */
int fp_sqrmod(fp_int *a, fp_int *b, fp_int *c);

/* c = 1/a (mod b) */
int fp_invmod(fp_int *a, fp_int *b, fp_int *c);

/* c = (a, b) */
/*int fp_gcd(fp_int *a, fp_int *b, fp_int *c);*/

/* c = [a, b] */
/*int fp_lcm(fp_int *a, fp_int *b, fp_int *c);*/

/* setups the montgomery reduction */
int fp_montgomery_setup(fp_int *a, fp_digit *mp);

/* computes a = B**n mod b without division or multiplication useful for
 * normalizing numbers in a Montgomery system.
 */
void fp_montgomery_calc_normalization(fp_int *a, fp_int *b);

/* computes x/R == x (mod N) via Montgomery Reduction */
int fp_montgomery_reduce(fp_int *a, fp_int *m, fp_digit mp);

/* d = a**b (mod c) */
int fp_exptmod(fp_int *a, fp_int *b, fp_int *c, fp_int *d);
int fp_exptmod_ex(fp_int *a, fp_int *b, int minDigits, fp_int *c, fp_int *d);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -535,6 +535,7 @@
 
 /* c = 1/a (mod b) */
 int fp_invmod(fp_int *a, fp_int *b, fp_int *c);
+int fp_invmod_mont_ct(fp_int *a, fp_int *b, fp_int *c, fp_digit mp);
 
 /* c = (a, b) */
 /*int fp_gcd(fp_int *a, fp_int *b, fp_int *c);*/
@@ -743,6 +744,7 @@
 MP_API int  mp_addmod (mp_int* a, mp_int* b, mp_int* c, mp_int* d);
 MP_API int  mp_mod(mp_int *a, mp_int *b, mp_int *c);
 MP_API int  mp_invmod(mp_int *a, mp_int *b, mp_int *c);
+MP_API int  mp_invmod_mont_ct(mp_int *a, mp_int *b, mp_int *c, fp_digit mp);
 MP_API int  mp_exptmod (mp_int * g, mp_int * x, mp_int * p, mp_int * y);
 MP_API int  mp_exptmod_ex (mp_int * g, mp_int * x, int minDigits, mp_int * p,
                            mp_int * y);
```
