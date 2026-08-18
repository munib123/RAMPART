# CrossVul Fix Pair: Use of a Broken or Risky Cryptographic Algorithm in c
**Pair ID:** 1336_1
**Vulnerability Class:** Use of a Broken or Risky Cryptographic Algorithm
**CWE:** CWE-327
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1336_1`)

## Vulnerability Information & PoC

## Description
Use of a Broken or Risky Cryptographic Algorithm - Cryptographic algorithms are the methods by which data is scrambled to prevent observation or influence by unauthorized actors.

## Vulnerable Code
```c
Lines 45-76 of the vulnerable file.

WOLFSSL_API int wc_SignatureGetSize(enum wc_SignatureType sig_type,
    const void* key, word32 key_len);

WOLFSSL_API int wc_SignatureVerifyHash(
    enum wc_HashType hash_type, enum wc_SignatureType sig_type,
    const byte* hash_data, word32 hash_len,
    const byte* sig, word32 sig_len,
    const void* key, word32 key_len);

WOLFSSL_API int wc_SignatureVerify(
    enum wc_HashType hash_type, enum wc_SignatureType sig_type,
    const byte* data, word32 data_len,
    const byte* sig, word32 sig_len,
    const void* key, word32 key_len);

WOLFSSL_API int wc_SignatureGenerateHash(
    enum wc_HashType hash_type, enum wc_SignatureType sig_type,
    const byte* hash_data, word32 hash_len,
    byte* sig, word32 *sig_len,
    const void* key, word32 key_len, WC_RNG* rng);
WOLFSSL_API int wc_SignatureGenerate(
    enum wc_HashType hash_type, enum wc_SignatureType sig_type,
    const byte* data, word32 data_len,
    byte* sig, word32 *sig_len,
    const void* key, word32 key_len,
    WC_RNG* rng);

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLF_CRYPT_SIGNATURE_H */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -62,12 +62,23 @@
     const byte* hash_data, word32 hash_len,
     byte* sig, word32 *sig_len,
     const void* key, word32 key_len, WC_RNG* rng);
+WOLFSSL_API int wc_SignatureGenerateHash_ex(
+    enum wc_HashType hash_type, enum wc_SignatureType sig_type,
+    const byte* hash_data, word32 hash_len,
+    byte* sig, word32 *sig_len,
+    const void* key, word32 key_len, WC_RNG* rng, int verify);
 WOLFSSL_API int wc_SignatureGenerate(
     enum wc_HashType hash_type, enum wc_SignatureType sig_type,
     const byte* data, word32 data_len,
     byte* sig, word32 *sig_len,
     const void* key, word32 key_len,
     WC_RNG* rng);
+WOLFSSL_API int wc_SignatureGenerate_ex(
+    enum wc_HashType hash_type, enum wc_SignatureType sig_type,
+    const byte* data, word32 data_len,
+    byte* sig, word32 *sig_len,
+    const void* key, word32 key_len,
+    WC_RNG* rng, int verify);
 
 #ifdef __cplusplus
     } /* extern "C" */
```
