# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 187_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `187_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 3122-3167 of the vulnerable file.

    byte  buf[ECC_MAXSIZE_GEN];
#endif

#ifdef WOLFSSL_SMALL_STACK
    buf = (byte*)XMALLOC(ECC_MAXSIZE_GEN, NULL, DYNAMIC_TYPE_ECC_BUFFER);
    if (buf == NULL)
        return MEMORY_E;
#endif

    /*generate 8 extra bytes to mitigate bias from the modulo operation below*/
    /*see section A.1.2 in 'Suite B Implementor's Guide to FIPS 186-3 (ECDSA)'*/
    size += 8;

    /* make up random string */
    err = wc_RNG_GenerateBlock(rng, buf, size);

    /* load random buffer data into k */
    if (err == 0)
        err = mp_read_unsigned_bin(k, (byte*)buf, size);

    /* quick sanity check to make sure we're not dealing with a 0 key */
    if (err == MP_OKAY) {
        if (mp_iszero(k) == MP_YES)
          err = MP_ZERO_E;
    }

    /* the key should be smaller than the order of base point */
    if (err == MP_OKAY) {
        if (mp_cmp(k, order) != MP_LT) {
            err = mp_mod(k, order, k);
        }
    }

    ForceZero(buf, ECC_MAXSIZE);
#ifdef WOLFSSL_SMALL_STACK
    XFREE(buf, NULL, DYNAMIC_TYPE_ECC_BUFFER);
#endif

    return err;
}
#endif
#endif /* !WOLFSSL_ATECC508A */

static INLINE void wc_ecc_reset(ecc_key* key)
{
    /* make sure required key variables are reset */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3139,17 +3139,17 @@
     if (err == 0)
         err = mp_read_unsigned_bin(k, (byte*)buf, size);
 
-    /* quick sanity check to make sure we're not dealing with a 0 key */
-    if (err == MP_OKAY) {
-        if (mp_iszero(k) == MP_YES)
-          err = MP_ZERO_E;
-    }
-
     /* the key should be smaller than the order of base point */
     if (err == MP_OKAY) {
         if (mp_cmp(k, order) != MP_LT) {
             err = mp_mod(k, order, k);
         }
+    }
+
+    /* quick sanity check to make sure we're not dealing with a 0 key */
+    if (err == MP_OKAY) {
+        if (mp_iszero(k) == MP_YES)
+          err = MP_ZERO_E;
     }
 
     ForceZero(buf, ECC_MAXSIZE);
@@ -3924,12 +3924,32 @@
 
        /* don't use async for key, since we don't support async return here */
        if ((err = wc_ecc_init_ex(&pubkey, key->heap, INVALID_DEVID)) == MP_OKAY) {
+           mp_int b;
+
+           if (err == MP_OKAY) {
+               err = mp_init(&b);
+           }
+
        #ifdef WOLFSSL_CUSTOM_CURVES
            /* if custom curve, apply params to pubkey */
-           if (key->idx == ECC_CUSTOM_IDX) {
+           if (err == MP_OKAY && key->idx == ECC_CUSTOM_IDX) {
                err = wc_ecc_set_custom_curve(&pubkey, key->dp);
            }
        #endif
+
+           if (err == MP_OKAY) {
+               /* Generate blinding value - non-zero value. */
+               do {
+                   if (++loop_check > 64) {
+                        err = RNG_FAILURE_E;
+                        break;
+                   }
+
+                   err = wc_ecc_gen_k(rng, key->dp->size, &b, curve->order);
+               }
+               while (err == MP_ZERO_E);
+               loop_check = 0;
+           }
 
            for (; err == MP_OKAY;) {
                if (++loop_check > 64) {
@@ -3937,7 +3957,7 @@
                     break;
                }
                err = wc_ecc_make_key_ex(rng, key->dp->size, &pubkey,
-                                                              key->dp->id);
+                                                                   key->dp->id);
                if (err != MP_OKAY) break;
 
                /* find r = x1 mod n */
@@ -3953,30 +3973,50 @@
                    mp_forcezero(&pubkey.k);
                }
                else {
-                   /* find s = (e + xr)/k */
+                   /* find s = (e + xr)/k
+                             = b.(e/k.b + x.r/k.b) */
+
+                   /* k = k.b */
+                   err = mp_mulmod(&pubkey.k, &b, curve->order, &pubkey.k);
+                   if (err != MP_OKAY) break;
+
+                   /* k = 1/k.b */
                    err = mp_invmod(&pubkey.k, curve->order, &pubkey.k);
                    if (err != MP_OKAY) break;
 
-                   /* s = xr */
+                   /* s = x.r */
                    err = mp_mulmod(&key->k, r, curve->order, s);
                    if (err != MP_OKAY) break;
 
-                   /* s = e +  xr */
+                   /* s = x.r/k.b */
+                   err = mp_mulmod(&pubkey.k, s, curve->order, s);
+                   if (err != MP_OKAY) break;
+
+                   /* e = e/k.b */
+                   err = mp_mulmod(&pubkey.k, e, curve->order, e);
+                   if (err != MP_OKAY) break;
+
+                   /* s = e/k.b + x.r/k.b
+                        = (e + x.r)/k.b */
                    err = mp_add(e, s, s);
                    if (err != MP_OKAY) break;
 
-                   /* s = e +  xr */
+                   /* s = b.(e + x.r)/k.b
+                        = (e + x.r)/k */
+                   err = mp_mulmod(s, &b, curve->order, s);
+                   if (err != MP_OKAY) break;
+
+                   /* s = (e + xr)/k */
                    err = mp_mod(s, curve->order, s);
                    if (err != MP_OKAY) break;
-
-                   /* s = (e + xr)/k */
-                   err = mp_mulmod(s, &pubkey.k, curve->order, s);
 
                    if (mp_iszero(s) == MP_NO)
                        break;
                 }
            }
            wc_ecc_free(&pubkey);
+           mp_clear(&b);
+           mp_free(&b);
        }
    }
 
```
