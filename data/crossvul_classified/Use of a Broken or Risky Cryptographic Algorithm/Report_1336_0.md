# CrossVul Fix Pair: Use of a Broken or Risky Cryptographic Algorithm in c
**Pair ID:** 1336_0
**Vulnerability Class:** Use of a Broken or Risky Cryptographic Algorithm
**CWE:** CWE-327
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1336_0`)

## Vulnerability Information & PoC

## Description
Use of a Broken or Risky Cryptographic Algorithm - Cryptographic algorithms are the methods by which data is scrambled to prevent observation or influence by unauthorized actors.

## Vulnerable Code
```c
Lines 303-343 of the vulnerable file.

            /* Verify signature using hash */
            ret = wc_SignatureVerifyHash(hash_type, sig_type,
                hash_data, hash_enc_len, sig, sig_len, key, key_len);
        }
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(hash_data, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}


int wc_SignatureGenerateHash(
    enum wc_HashType hash_type, enum wc_SignatureType sig_type,
    const byte* hash_data, word32 hash_len,
    byte* sig, word32 *sig_len,
    const void* key, word32 key_len, WC_RNG* rng)
{
    int ret;

    /* Suppress possible unused arg if all signature types are disabled */
    (void)rng;

    /* Check arguments */
    if (hash_data == NULL || hash_len <= 0 ||
        sig == NULL || sig_len == NULL || *sig_len <= 0 ||
        key == NULL || key_len <= 0) {
        return BAD_FUNC_ARG;
    }

    /* Validate signature len (needs to be at least max) */
    if ((int)*sig_len < wc_SignatureGetSize(sig_type, key, key_len)) {
        WOLFSSL_MSG("wc_SignatureGenerate: Invalid sig type/len");
        return BAD_FUNC_ARG;
    }

    /* Validate hash size */
    ret = wc_HashGetDigestSize(hash_type);
    if (ret < 0) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -320,6 +320,16 @@
     byte* sig, word32 *sig_len,
     const void* key, word32 key_len, WC_RNG* rng)
 {
+    return wc_SignatureGenerateHash_ex(hash_type, sig_type, hash_data, hash_len,
+        sig, sig_len, key, key_len, rng, 1);
+}
+
+int wc_SignatureGenerateHash_ex(
+    enum wc_HashType hash_type, enum wc_SignatureType sig_type,
+    const byte* hash_data, word32 hash_len,
+    byte* sig, word32 *sig_len,
+    const void* key, word32 key_len, WC_RNG* rng, int verify)
+{
     int ret;
 
     /* Suppress possible unused arg if all signature types are disabled */
@@ -393,6 +403,11 @@
             break;
     }
 
+    if (ret == 0 && verify) {
+        ret = wc_SignatureVerifyHash(hash_type, sig_type, hash_data, hash_len,
+            sig, *sig_len, key, key_len);
+    }
+
     return ret;
 }
 
@@ -401,6 +416,16 @@
     const byte* data, word32 data_len,
     byte* sig, word32 *sig_len,
     const void* key, word32 key_len, WC_RNG* rng)
+{
+    return wc_SignatureGenerate_ex(hash_type, sig_type, data, data_len, sig,
+        sig_len, key, key_len, rng, 1);
+}
+
+int wc_SignatureGenerate_ex(
+    enum wc_HashType hash_type, enum wc_SignatureType sig_type,
+    const byte* data, word32 data_len,
+    byte* sig, word32 *sig_len,
+    const void* key, word32 key_len, WC_RNG* rng, int verify)
 {
     int ret;
     word32 hash_len, hash_enc_len;
@@ -467,6 +492,11 @@
         }
     }
 
+    if (ret == 0 && verify) {
+        ret = wc_SignatureVerifyHash(hash_type, sig_type, hash_data,
+            hash_enc_len, sig, *sig_len, key, key_len);
+    }
+
 #ifdef WOLFSSL_SMALL_STACK
     XFREE(hash_data, NULL, DYNAMIC_TYPE_TMP_BUFFER);
 #endif
```
