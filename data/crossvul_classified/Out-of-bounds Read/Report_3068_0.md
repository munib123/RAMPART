# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 3068_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3068_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1371-1411 of the vulnerable file.

    case EVP_CTRL_GCM_SET_IV_INV:
        if (gctx->iv_gen == 0 || gctx->key_set == 0
            || EVP_CIPHER_CTX_encrypting(c))
            return 0;
        memcpy(gctx->iv + gctx->ivlen - arg, ptr, arg);
        CRYPTO_gcm128_setiv(&gctx->gcm, gctx->iv, gctx->ivlen);
        gctx->iv_set = 1;
        return 1;

    case EVP_CTRL_AEAD_TLS1_AAD:
        /* Save the AAD for later use */
        if (arg != EVP_AEAD_TLS1_AAD_LEN)
            return 0;
        memcpy(EVP_CIPHER_CTX_buf_noconst(c), ptr, arg);
        gctx->tls_aad_len = arg;
        {
            unsigned int len =
                EVP_CIPHER_CTX_buf_noconst(c)[arg - 2] << 8
                | EVP_CIPHER_CTX_buf_noconst(c)[arg - 1];
            /* Correct length for explicit IV */
            len -= EVP_GCM_TLS_EXPLICIT_IV_LEN;
            /* If decrypting correct for tag too */
            if (!EVP_CIPHER_CTX_encrypting(c))
                len -= EVP_GCM_TLS_TAG_LEN;
            EVP_CIPHER_CTX_buf_noconst(c)[arg - 2] = len >> 8;
            EVP_CIPHER_CTX_buf_noconst(c)[arg - 1] = len & 0xff;
        }
        /* Extra padding: tag appended to record */
        return EVP_GCM_TLS_TAG_LEN;

    case EVP_CTRL_COPY:
        {
            EVP_CIPHER_CTX *out = ptr;
            EVP_AES_GCM_CTX *gctx_out = EVP_C_DATA(EVP_AES_GCM_CTX,out);
            if (gctx->gcm.key) {
                if (gctx->gcm.key != &gctx->ks)
                    return 0;
                gctx_out->gcm.key = &gctx_out->ks;
            }
            if (gctx->iv == EVP_CIPHER_CTX_iv_noconst(c))
                gctx_out->iv = EVP_CIPHER_CTX_iv_noconst(out);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1388,10 +1388,15 @@
                 EVP_CIPHER_CTX_buf_noconst(c)[arg - 2] << 8
                 | EVP_CIPHER_CTX_buf_noconst(c)[arg - 1];
             /* Correct length for explicit IV */
+            if (len < EVP_GCM_TLS_EXPLICIT_IV_LEN)
+                return 0;
             len -= EVP_GCM_TLS_EXPLICIT_IV_LEN;
             /* If decrypting correct for tag too */
-            if (!EVP_CIPHER_CTX_encrypting(c))
+            if (!EVP_CIPHER_CTX_encrypting(c)) {
+                if (len < EVP_GCM_TLS_TAG_LEN)
+                    return 0;
                 len -= EVP_GCM_TLS_TAG_LEN;
+            }
             EVP_CIPHER_CTX_buf_noconst(c)[arg - 2] = len >> 8;
             EVP_CIPHER_CTX_buf_noconst(c)[arg - 1] = len & 0xff;
         }
@@ -1946,10 +1951,15 @@
                 EVP_CIPHER_CTX_buf_noconst(c)[arg - 2] << 8
                 | EVP_CIPHER_CTX_buf_noconst(c)[arg - 1];
             /* Correct length for explicit IV */
+            if (len < EVP_CCM_TLS_EXPLICIT_IV_LEN)
+                return 0;
             len -= EVP_CCM_TLS_EXPLICIT_IV_LEN;
             /* If decrypting correct for tag too */
-            if (!EVP_CIPHER_CTX_encrypting(c))
+            if (!EVP_CIPHER_CTX_encrypting(c)) {
+                if (len < cctx->M)
+                    return 0;
                 len -= cctx->M;
+            }
             EVP_CIPHER_CTX_buf_noconst(c)[arg - 2] = len >> 8;
             EVP_CIPHER_CTX_buf_noconst(c)[arg - 1] = len & 0xff;
         }
```
