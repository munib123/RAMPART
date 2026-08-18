# CrossVul Fix Pair: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') in c
**Pair ID:** 3927_2
**Vulnerability Class:** Classic Buffer Overflow
**CWE:** CWE-120
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3927_2`)

## Vulnerability Information & PoC

## Description
Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') - A buffer overflow condition exists when a product attempts to put more data in a buffer than it can hold, or when it attempts to put data in a memory area outside of the boundaries of a buffer.

## Vulnerable Code
```c
Lines 273-313 of the vulnerable file.

    lr1110_crypto_derive_and_store_key( &LR1110, ( lr1110_crypto_status_t* ) &status,
                                        convert_key_id_from_se_to_lr1110( rootKeyID ),
                                        convert_key_id_from_se_to_lr1110( targetKeyID ), input );

    lr1110_crypto_store_to_flash( &LR1110, ( lr1110_crypto_status_t* ) &status );
    return status;
}

SecureElementStatus_t SecureElementProcessJoinAccept( JoinReqIdentifier_t joinReqType, uint8_t* joinEui,
                                                      uint16_t devNonce, uint8_t* encJoinAccept,
                                                      uint8_t encJoinAcceptSize, uint8_t* decJoinAccept,
                                                      uint8_t* versionMinor )
{
    SecureElementStatus_t status = SECURE_ELEMENT_ERROR;

    if( ( encJoinAccept == NULL ) || ( decJoinAccept == NULL ) || ( versionMinor == NULL ) )
    {
        return SECURE_ELEMENT_ERROR_NPE;
    }

    // Determine decryption key
    KeyIdentifier_t encKeyID = NWK_KEY;

    if( joinReqType != JOIN_REQ )
    {
        encKeyID = J_S_ENC_KEY;
    }

    //  - Header buffer to be used for MIC computation
    //        - LoRaWAN 1.0.x : micHeader = [MHDR(1)]
    //        - LoRaWAN 1.1.x : micHeader = [JoinReqType(1), JoinEUI(8), DevNonce(2), MHDR(1)]

    // Try first to process LoRaWAN 1.0.x JoinAccept
    uint8_t micHeader10[1] = { 0x20 };

    //   cmac = aes128_cmac(NwkKey, MHDR |  JoinNonce | NetID | DevAddr | DLSettings | RxDelay | CFList |
    //   CFListType)
    lr1110_crypto_process_join_accept(
        &LR1110, ( lr1110_crypto_status_t* ) &status, convert_key_id_from_se_to_lr1110( encKeyID ),
        convert_key_id_from_se_to_lr1110( NWK_KEY ), ( lr1110_crypto_lorawan_version_t ) 0, micHeader10,
        encJoinAccept + 1, encJoinAcceptSize - 1, decJoinAccept + 1 );
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -290,6 +290,12 @@
         return SECURE_ELEMENT_ERROR_NPE;
     }
 
+    // Check that frame size isn't bigger than a JoinAccept with CFList size
+    if( encJoinAcceptSize > LORAMAC_JOIN_ACCEPT_FRAME_MAX_SIZE )
+    {
+        return SECURE_ELEMENT_ERROR_BUF_SIZE;
+    }
+
     // Determine decryption key
     KeyIdentifier_t encKeyID = NWK_KEY;
 
```
