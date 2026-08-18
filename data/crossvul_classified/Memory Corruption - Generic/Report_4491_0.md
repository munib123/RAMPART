# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 4491_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4491_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 1099-1139 of the vulnerable file.

 * inputLen      Length of digest.
 * pkcsBlock     Buffer to write to.
 * pkcsBlockLen  Length of buffer to write to.
 * rng           Random number generator (for salt).
 * htype         Hash function to use.
 * mgf           Mask generation function.
 * saltLen       Length of salt to put in padding.
 * bits          Length of key in bits.
 * heap          Used for dynamic memory allocation.
 * returns 0 on success, PSS_SALTLEN_E when the salt length is invalid
 * and other negative values on error.
 */
static int RsaPad_PSS(const byte* input, word32 inputLen, byte* pkcsBlock,
        word32 pkcsBlockLen, WC_RNG* rng, enum wc_HashType hType, int mgf,
        int saltLen, int bits, void* heap)
{
    int   ret = 0;
    int   hLen, i, o, maskLen, hiBits;
    byte* m;
    byte* s;
#if defined(WOLFSSL_PSS_LONG_SALT) || defined(WOLFSSL_PSS_SALT_LEN_DISCOVER)
    #if defined(WOLFSSL_NO_MALLOC) && !defined(WOLFSSL_STATIC_MEMORY)
        byte salt[RSA_MAX_SIZE/8 + RSA_PSS_PAD_SZ];
    #else
        byte* salt = NULL;
    #endif
#else
    byte salt[WC_MAX_DIGEST_SIZE];
#endif

#if defined(WOLFSSL_PSS_LONG_SALT) || defined(WOLFSSL_PSS_SALT_LEN_DISCOVER)
    if (pkcsBlockLen > RSA_MAX_SIZE/8) {
        return MEMORY_E;
    }
#endif

    hLen = wc_HashGetDigestSize(hType);
    if (hLen < 0)
        return hLen;
    if ((int)inputLen != hLen) {
        return BAD_FUNC_ARG;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1116,12 +1116,13 @@
     int   hLen, i, o, maskLen, hiBits;
     byte* m;
     byte* s;
+#if defined(WOLFSSL_NO_MALLOC) && !defined(WOLFSSL_STATIC_MEMORY)
+    byte msg[RSA_MAX_SIZE/8 + RSA_PSS_PAD_SZ];
+#else
+    byte* msg = NULL;
+#endif
 #if defined(WOLFSSL_PSS_LONG_SALT) || defined(WOLFSSL_PSS_SALT_LEN_DISCOVER)
-    #if defined(WOLFSSL_NO_MALLOC) && !defined(WOLFSSL_STATIC_MEMORY)
-        byte salt[RSA_MAX_SIZE/8 + RSA_PSS_PAD_SZ];
-    #else
-        byte* salt = NULL;
-    #endif
+    byte* salt;
 #else
     byte salt[WC_MAX_DIGEST_SIZE];
 #endif
@@ -1184,13 +1185,13 @@
 
 #if defined(WOLFSSL_PSS_LONG_SALT) || defined(WOLFSSL_PSS_SALT_LEN_DISCOVER)
     #if !defined(WOLFSSL_NO_MALLOC) || defined(WOLFSSL_STATIC_MEMORY)
-        salt = (byte*)XMALLOC(RSA_PSS_PAD_SZ + inputLen + saltLen, heap,
+        msg = (byte*)XMALLOC(RSA_PSS_PAD_SZ + inputLen + saltLen, heap,
                                                        DYNAMIC_TYPE_RSA_BUFFER);
-        if (salt == NULL) {
+        if (msg == NULL) {
             return MEMORY_E;
         }
     #endif
-    s = m = salt;
+    salt = s = m = msg;
     XMEMSET(m, 0, RSA_PSS_PAD_SZ);
     m += RSA_PSS_PAD_SZ;
     XMEMCPY(m, input, inputLen);
@@ -1203,7 +1204,20 @@
         }
     }
 #else
-    s = m = pkcsBlock;
+    if (pkcsBlockLen < RSA_PSS_PAD_SZ + inputLen + saltLen) {
+    #if !defined(WOLFSSL_NO_MALLOC) || defined(WOLFSSL_STATIC_MEMORY)
+        msg = (byte*)XMALLOC(RSA_PSS_PAD_SZ + inputLen + saltLen, heap,
+                                                       DYNAMIC_TYPE_RSA_BUFFER);
+        if (msg == NULL) {
+            return MEMORY_E;
+        }
+    #endif
+        m = msg;
+    }
+    else {
+        m = pkcsBlock;
+    }
+    s = m;
     XMEMSET(m, 0, RSA_PSS_PAD_SZ);
     m += RSA_PSS_PAD_SZ;
     XMEMCPY(m, input, inputLen);
@@ -1240,13 +1254,11 @@
         }
     }
 
-#if defined(WOLFSSL_PSS_LONG_SALT) || defined(WOLFSSL_PSS_SALT_LEN_DISCOVER)
     #if !defined(WOLFSSL_NO_MALLOC) || defined(WOLFSSL_STATIC_MEMORY)
-        if (salt != NULL) {
-            XFREE(salt, heap, DYNAMIC_TYPE_RSA_BUFFER);
+        if (msg != NULL) {
+            XFREE(msg, heap, DYNAMIC_TYPE_RSA_BUFFER);
         }
     #endif
-#endif
     return ret;
 }
 #endif /* WC_RSA_PSS */
```
