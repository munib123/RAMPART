# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 5106_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5106_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 334-374 of the vulnerable file.

    AIRPDCAP_SEC_ASSOCIATION *tmp_sa;

    /* We skip verifying the MIC of the key. If we were implementing a WPA supplicant we'd want to verify, but for a sniffer it's not needed. */

    /* Preparation for decrypting the group key -  determine group key data length */
    /* depending on whether the pairwise key is TKIP or AES encryption key */
    key_version = AIRPDCAP_EAP_KEY_DESCR_VER(pEAPKey->key_information[1]);
    if (key_version == AIRPDCAP_WPA_KEY_VER_NOT_CCMP){
        /* TKIP */
        key_bytes_len = pntoh16(pEAPKey->key_length);
    }else if (key_version == AIRPDCAP_WPA_KEY_VER_AES_CCMP){
        /* AES */
        key_bytes_len = pntoh16(pEAPKey->key_data_len);

        /* AES keys must be at least 128 bits = 16 bytes. */
        if (key_bytes_len < 16) {
            return AIRPDCAP_RET_NO_VALID_HANDSHAKE;
        }
    }

    if (key_bytes_len < GROUP_KEY_MIN_LEN || key_bytes_len > eapol_len - sizeof(EAPOL_RSN_KEY)) {
        return AIRPDCAP_RET_NO_VALID_HANDSHAKE;
    }

    /* Encrypted key is in the information element field of the EAPOL key packet */
    key_data = (guint8 *)pEAPKey + sizeof(EAPOL_RSN_KEY);
    szEncryptedKey = (guint8 *)g_memdup(key_data, key_bytes_len);

    DEBUG_DUMP("Encrypted Broadcast key:", szEncryptedKey, key_bytes_len);
    DEBUG_DUMP("KeyIV:", pEAPKey->key_iv, 16);
    DEBUG_DUMP("decryption_key:", decryption_key, 16);

    /* We are rekeying, save old sa */
    tmp_sa=(AIRPDCAP_SEC_ASSOCIATION *)g_malloc(sizeof(AIRPDCAP_SEC_ASSOCIATION));
    memcpy(tmp_sa, sa, sizeof(AIRPDCAP_SEC_ASSOCIATION));
    sa->next=tmp_sa;

    /* As we have no concept of the prior association request at this point, we need to deduce the     */
    /* group key cipher from the length of the key bytes. In WPA this is straightforward as the        */
    /* keybytes just contain the GTK, and the GTK is only in the group handshake, NOT the M3.          */
    /* In WPA2 its a little more tricky as the M3 keybytes contain an RSN_IE, but the group handshake  */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -351,7 +351,9 @@
         }
     }
 
-    if (key_bytes_len < GROUP_KEY_MIN_LEN || key_bytes_len > eapol_len - sizeof(EAPOL_RSN_KEY)) {
+    if ((key_bytes_len < GROUP_KEY_MIN_LEN) ||
+        (eapol_len < sizeof(EAPOL_RSN_KEY)) ||
+        (key_bytes_len > eapol_len - sizeof(EAPOL_RSN_KEY))) {
         return AIRPDCAP_RET_NO_VALID_HANDSHAKE;
     }
 
```
