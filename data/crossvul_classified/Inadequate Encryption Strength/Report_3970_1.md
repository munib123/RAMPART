# CrossVul Fix Pair: Inadequate Encryption Strength in c
**Pair ID:** 3970_1
**Vulnerability Class:** Inadequate Encryption Strength
**CWE:** CWE-326
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3970_1`)

## Vulnerability Information & PoC

## Description
Inadequate Encryption Strength - A weak encryption scheme can be subjected to brute force attacks that have a reasonable chance of succeeding using current attack methods and resources.

## Vulnerable Code
```c
Lines 1139-1179 of the vulnerable file.

  if (fp_cmp_d (v, 1) != FP_EQ) {
  #ifdef WOLFSSL_SMALL_STACK
    XFREE(x, NULL, DYNAMIC_TYPE_BIGINT);
  #endif
    return FP_VAL;
  }

  /* b is now the inverse */
  neg = a->sign;
  while (D->sign == FP_NEG) {
    fp_add (D, b, D);
  }
  /* too big */
  while (fp_cmp_mag(D, b) != FP_LT) {
    fp_sub(D, b, D);
  }
  fp_copy (D, c);
  c->sign = neg;
#ifdef WOLFSSL_SMALL_STACK
  XFREE(x, NULL, DYNAMIC_TYPE_BIGINT);
#endif
  return FP_OKAY;
}

/* d = a * b (mod c) */
int fp_mulmod(fp_int *a, fp_int *b, fp_int *c, fp_int *d)
{
  int err;
#ifndef WOLFSSL_SMALL_STACK
   fp_int t[1];
#else
   fp_int *t;
#endif

#ifdef WOLFSSL_SMALL_STACK
   t = (fp_int*)XMALLOC(sizeof(fp_int), NULL, DYNAMIC_TYPE_BIGINT);
   if (t == NULL)
       return FP_MEM;
#endif

  fp_init(t);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1156,6 +1156,75 @@
   c->sign = neg;
 #ifdef WOLFSSL_SMALL_STACK
   XFREE(x, NULL, DYNAMIC_TYPE_BIGINT);
+#endif
+  return FP_OKAY;
+}
+
+#define CT_INV_MOD_PRE_CNT      8
+
+/* modulus (b) must be greater than 2 and a prime */
+int fp_invmod_mont_ct(fp_int *a, fp_int *b, fp_int *c, fp_digit mp)
+{
+  int i, j;
+#ifndef WOLFSSL_SMALL_STACK
+  fp_int t[1], e[1];
+  fp_int pre[CT_INV_MOD_PRE_CNT];
+#else
+  fp_int* t;
+  fp_int* e;
+  fp_int* pre;
+#endif
+
+#ifdef WOLFSSL_SMALL_STACK
+  t = (fp_int*)XMALLOC(sizeof(fp_int) * (2 + CT_INV_MOD_PRE_CNT), NULL,
+                                                           DYNAMIC_TYPE_BIGINT);
+  if (t == NULL)
+    return FP_MEM;
+  e = t + 1;
+  pre = t + 2;
+#endif
+
+  fp_init(t);
+  fp_init(e);
+
+  fp_init(&pre[0]);
+  fp_copy(a, &pre[0]);
+  for (i = 1; i < CT_INV_MOD_PRE_CNT; i++) {
+    fp_init(&pre[i]);
+    fp_sqr(&pre[i-1], &pre[i]);
+    fp_montgomery_reduce(&pre[i], b, mp);
+    fp_mul(&pre[i], a, &pre[i]);
+    fp_montgomery_reduce(&pre[i], b, mp);
+  }
+
+  fp_sub_d(b, 2, e);
+  /* Highest bit is always set. */
+  for (i = fp_count_bits(e)-2, j = 1; i >= 0; i--, j++) {
+      if (!fp_is_bit_set(e, i) || j == CT_INV_MOD_PRE_CNT)
+          break;
+  }
+  fp_copy(&pre[j-1], t);
+  for (j = 0; i >= 0; i--) {
+    int set = fp_is_bit_set(e, i);
+
+    if ((j == CT_INV_MOD_PRE_CNT) || (!set && j > 0)) {
+      fp_mul(t, &pre[j-1], t);
+      fp_montgomery_reduce(t, b, mp);
+      j = 0;
+    }
+    fp_sqr(t, t);
+    fp_montgomery_reduce(t, b, mp);
+    j += set;
+  }
+  if (j > 0) {
+    fp_mul(t, &pre[j-1], c);
+    fp_montgomery_reduce(c, b, mp);
+  }
+  else 
+    fp_copy(t, c);
+
+#ifdef WOLFSSL_SMALL_STACK
+  XFREE(t, NULL, DYNAMIC_TYPE_BIGINT);
 #endif
   return FP_OKAY;
 }
@@ -3545,6 +3614,12 @@
   return fp_invmod(a, b, c);
 }
 
+/* hac 14.61, pp608 */
+int mp_invmod_mont_ct (mp_int * a, mp_int * b, mp_int * c, mp_digit mp)
+{
+  return fp_invmod_mont_ct(a, b, c, mp);
+}
+
 /* this is a shell function that calls either the normal or Montgomery
  * exptmod functions.  Originally the call to the montgomery code was
  * embedded in the normal function but that wasted a lot of stack space
```
