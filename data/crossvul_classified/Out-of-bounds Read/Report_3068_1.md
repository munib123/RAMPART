# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 3068_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3068_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 381-421 of the vulnerable file.

            actx->tag_len = arg;
        }
        return 1;

    case EVP_CTRL_AEAD_GET_TAG:
        if (arg <= 0 || arg > POLY1305_BLOCK_SIZE || !ctx->encrypt)
            return 0;
        memcpy(ptr, actx->tag, arg);
        return 1;

    case EVP_CTRL_AEAD_TLS1_AAD:
        if (arg != EVP_AEAD_TLS1_AAD_LEN)
            return 0;
        {
            unsigned int len;
            unsigned char *aad = ptr, temp[POLY1305_BLOCK_SIZE];

            len = aad[EVP_AEAD_TLS1_AAD_LEN - 2] << 8 |
                  aad[EVP_AEAD_TLS1_AAD_LEN - 1];
            if (!ctx->encrypt) {
                len -= POLY1305_BLOCK_SIZE;     /* discount attached tag */
                memcpy(temp, aad, EVP_AEAD_TLS1_AAD_LEN - 2);
                aad = temp;
                temp[EVP_AEAD_TLS1_AAD_LEN - 2] = (unsigned char)(len >> 8);
                temp[EVP_AEAD_TLS1_AAD_LEN - 1] = (unsigned char)len;
            }
            actx->tls_payload_length = len;

            /*
             * merge record sequence number as per
             * draft-ietf-tls-chacha20-poly1305-03
             */
            actx->key.counter[1] = actx->nonce[0];
            actx->key.counter[2] = actx->nonce[1] ^ CHACHA_U8TOU32(aad);
            actx->key.counter[3] = actx->nonce[2] ^ CHACHA_U8TOU32(aad+4);
            actx->mac_inited = 0;
            chacha20_poly1305_cipher(ctx, NULL, aad, EVP_AEAD_TLS1_AAD_LEN);
            return POLY1305_BLOCK_SIZE;         /* tag length */
        }

    case EVP_CTRL_AEAD_SET_MAC_KEY:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -398,6 +398,8 @@
             len = aad[EVP_AEAD_TLS1_AAD_LEN - 2] << 8 |
                   aad[EVP_AEAD_TLS1_AAD_LEN - 1];
             if (!ctx->encrypt) {
+                if (len < POLY1305_BLOCK_SIZE)
+                    return 0;
                 len -= POLY1305_BLOCK_SIZE;     /* discount attached tag */
                 memcpy(temp, aad, EVP_AEAD_TLS1_AAD_LEN - 2);
                 aad = temp;
@@ -407,8 +409,7 @@
             actx->tls_payload_length = len;
 
             /*
-             * merge record sequence number as per
-             * draft-ietf-tls-chacha20-poly1305-03
+             * merge record sequence number as per RFC7905
              */
             actx->key.counter[1] = actx->nonce[0];
             actx->key.counter[2] = actx->nonce[1] ^ CHACHA_U8TOU32(aad);
```
