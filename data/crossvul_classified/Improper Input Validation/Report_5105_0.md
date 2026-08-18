# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5105_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5105_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 554-594 of the vulnerable file.


    /* cache offset in the packet data */
    offset = mac_header_len;

    /* check if the packet has an LLC header and the packet is 802.1X authentication (IEEE 802.1X-2004, pg. 24) */
    if (memcmp(data+offset, dot1x_header, 8) == 0 || memcmp(data+offset, bt_dot1x_header, 8) == 0) {

        AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapScanForKeys", "Authentication: EAPOL packet", AIRPDCAP_DEBUG_LEVEL_3);

        /* skip LLC header */
        offset+=8;

        /* check if the packet is a EAPOL-Key (0x03) (IEEE 802.1X-2004, pg. 25) */
        if (data[offset+1]!=3) {
            AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapScanForKeys", "Not EAPOL-Key", AIRPDCAP_DEBUG_LEVEL_3);
            return AIRPDCAP_RET_NO_VALID_HANDSHAKE;
        }

        /* get and check the body length (IEEE 802.1X-2004, pg. 25) */
        bodyLength=pntoh16(data+offset+2);
        if ((tot_len-offset-4) < bodyLength) { /* Only check if frame is long enough for eapol header, ignore tailing garbage, see bug 9065 */
            AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapScanForKeys", "EAPOL body too short", AIRPDCAP_DEBUG_LEVEL_3);
            return AIRPDCAP_RET_NO_VALID_HANDSHAKE;
        }

        /* skip EAPOL MPDU and go to the first byte of the body */
        offset+=4;

        pEAPKey = (const EAPOL_RSN_KEY *) (data+offset);

        /* check if the key descriptor type is valid (IEEE 802.1X-2004, pg. 27) */
        if (/*pEAPKey->type!=0x1 &&*/ /* RC4 Key Descriptor Type (deprecated) */
            pEAPKey->type != AIRPDCAP_RSN_WPA2_KEY_DESCRIPTOR &&             /* IEEE 802.11 Key Descriptor Type  (WPA2) */
            pEAPKey->type != AIRPDCAP_RSN_WPA_KEY_DESCRIPTOR)           /* 254 = RSN_KEY_DESCRIPTOR - WPA,              */
        {
            AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapScanForKeys", "Not valid key descriptor type", AIRPDCAP_DEBUG_LEVEL_3);
            return AIRPDCAP_RET_NO_VALID_HANDSHAKE;
        }

        /* start with descriptor body */
        offset+=1;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -571,7 +571,7 @@
 
         /* get and check the body length (IEEE 802.1X-2004, pg. 25) */
         bodyLength=pntoh16(data+offset+2);
-        if ((tot_len-offset-4) < bodyLength) { /* Only check if frame is long enough for eapol header, ignore tailing garbage, see bug 9065 */
+        if (((tot_len-offset-4) < bodyLength) || (bodyLength < sizeof(EAPOL_RSN_KEY))) { /* Only check if frame is long enough for eapol header, ignore tailing garbage, see bug 9065 */
             AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapScanForKeys", "EAPOL body too short", AIRPDCAP_DEBUG_LEVEL_3);
             return AIRPDCAP_RET_NO_VALID_HANDSHAKE;
         }
```
