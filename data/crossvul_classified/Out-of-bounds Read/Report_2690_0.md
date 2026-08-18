# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2690_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2690_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 165-205 of the vulnerable file.

    if (ndo->ndo_vflag < 1) {
	ND_PRINT((ndo, "%s (%u) v%u, len %u",
               tok2str(eap_frame_type_values, "unknown", eap->type),
               eap->type,
               eap->version,
               EXTRACT_16BITS(eap->length)));
	return;
    }

    ND_PRINT((ndo, "%s (%u) v%u, len %u",
           tok2str(eap_frame_type_values, "unknown", eap->type),
           eap->type,
           eap->version,
           EXTRACT_16BITS(eap->length)));

    tptr += sizeof(const struct eap_frame_t);
    tlen -= sizeof(const struct eap_frame_t);

    switch (eap->type) {
    case EAP_FRAME_TYPE_PACKET:
        type = *(tptr);
        len = EXTRACT_16BITS(tptr+2);
        ND_PRINT((ndo, ", %s (%u), id %u, len %u",
               tok2str(eap_code_values, "unknown", type),
               type,
               *(tptr+1),
               len));

        ND_TCHECK2(*tptr, len);

        if (type <= 2) { /* For EAP_REQUEST and EAP_RESPONSE only */
            subtype = *(tptr+4);
            ND_PRINT((ndo, "\n\t\t Type %s (%u)",
                   tok2str(eap_type_values, "unknown", *(tptr+4)),
                   *(tptr + 4)));

            switch (subtype) {
            case EAP_TYPE_IDENTITY:
                if (len - 5 > 0) {
                    ND_PRINT((ndo, ", Identity: "));
                    safeputs(ndo, tptr + 5, len - 5);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -182,7 +182,9 @@
 
     switch (eap->type) {
     case EAP_FRAME_TYPE_PACKET:
+        ND_TCHECK_8BITS(tptr);
         type = *(tptr);
+        ND_TCHECK_16BITS(tptr+2);
         len = EXTRACT_16BITS(tptr+2);
         ND_PRINT((ndo, ", %s (%u), id %u, len %u",
                tok2str(eap_code_values, "unknown", type),
@@ -193,10 +195,11 @@
         ND_TCHECK2(*tptr, len);
 
         if (type <= 2) { /* For EAP_REQUEST and EAP_RESPONSE only */
+            ND_TCHECK_8BITS(tptr+4);
             subtype = *(tptr+4);
             ND_PRINT((ndo, "\n\t\t Type %s (%u)",
-                   tok2str(eap_type_values, "unknown", *(tptr+4)),
-                   *(tptr + 4)));
+                   tok2str(eap_type_values, "unknown", subtype),
+                   subtype));
 
             switch (subtype) {
             case EAP_TYPE_IDENTITY:
@@ -222,6 +225,7 @@
                  * type one octet per type
                  */
                 while (count < len) {
+                    ND_TCHECK_8BITS(tptr+count);
                     ND_PRINT((ndo, " %s (%u),",
                            tok2str(eap_type_values, "unknown", *(tptr+count)),
                            *(tptr + count)));
@@ -230,19 +234,23 @@
                 break;
 
             case EAP_TYPE_TTLS:
-                ND_PRINT((ndo, " TTLSv%u",
-                       EAP_TTLS_VERSION(*(tptr + 5)))); /* fall through */
             case EAP_TYPE_TLS:
+                ND_TCHECK_8BITS(tptr + 5);
+                if (subtype == EAP_TYPE_TTLS)
+                    ND_PRINT((ndo, " TTLSv%u",
+                           EAP_TTLS_VERSION(*(tptr + 5))));
                 ND_PRINT((ndo, " flags [%s] 0x%02x,",
                        bittok2str(eap_tls_flags_values, "none", *(tptr+5)),
                        *(tptr + 5)));
 
                 if (EAP_TLS_EXTRACT_BIT_L(*(tptr+5))) {
+                    ND_TCHECK_32BITS(tptr + 6);
 		    ND_PRINT((ndo, " len %u", EXTRACT_32BITS(tptr + 6)));
                 }
                 break;
 
             case EAP_TYPE_FAST:
+                ND_TCHECK_8BITS(tptr + 5);
                 ND_PRINT((ndo, " FASTv%u",
                        EAP_TTLS_VERSION(*(tptr + 5))));
                 ND_PRINT((ndo, " flags [%s] 0x%02x,",
@@ -250,6 +258,7 @@
                        *(tptr + 5)));
 
                 if (EAP_TLS_EXTRACT_BIT_L(*(tptr+5))) {
+                    ND_TCHECK_32BITS(tptr + 6);
                     ND_PRINT((ndo, " len %u", EXTRACT_32BITS(tptr + 6)));
                 }
 
@@ -258,6 +267,7 @@
 
             case EAP_TYPE_AKA:
             case EAP_TYPE_SIM:
+                ND_TCHECK_8BITS(tptr + 5);
                 ND_PRINT((ndo, " subtype [%s] 0x%02x,",
                        tok2str(eap_aka_subtype_values, "unknown", *(tptr+5)),
                        *(tptr + 5)));
```
