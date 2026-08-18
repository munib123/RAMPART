# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2644_7
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2644_7`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 776-816 of the vulnerable file.

        p+=l2info.header_len;

        /* first try the LSQ protos */
        switch(l2info.proto) {
        case JUNIPER_LSQ_L3_PROTO_IPV4:
            /* IP traffic going to the RE would not have a cookie
             * -> this must be incoming IS-IS over PPP
             */
            if (l2info.cookie[4] == (JUNIPER_LSQ_COOKIE_RE|JUNIPER_LSQ_COOKIE_DIR))
                ppp_print(ndo, p, l2info.length);
            else
                ip_print(ndo, p, l2info.length);
            return l2info.header_len;
        case JUNIPER_LSQ_L3_PROTO_IPV6:
            ip6_print(ndo, p,l2info.length);
            return l2info.header_len;
        case JUNIPER_LSQ_L3_PROTO_MPLS:
            mpls_print(ndo, p, l2info.length);
            return l2info.header_len;
        case JUNIPER_LSQ_L3_PROTO_ISO:
            isoclns_print(ndo, p, l2info.length, l2info.caplen);
            return l2info.header_len;
        default:
            break;
        }

        /* zero length cookie ? */
        switch (EXTRACT_16BITS(&l2info.cookie)) {
        case PPP_OSI:
            ppp_print(ndo, p - 2, l2info.length + 2);
            break;
        case (PPP_ADDRESS << 8 | PPP_CONTROL): /* fall through */
        default:
            ppp_print(ndo, p, l2info.length);
            break;
        }

        return l2info.header_len;
}
#endif

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -793,7 +793,7 @@
             mpls_print(ndo, p, l2info.length);
             return l2info.header_len;
         case JUNIPER_LSQ_L3_PROTO_ISO:
-            isoclns_print(ndo, p, l2info.length, l2info.caplen);
+            isoclns_print(ndo, p, l2info.length);
             return l2info.header_len;
         default:
             break;
@@ -848,7 +848,7 @@
                 mpls_print(ndo, p, l2info.length);
                 return l2info.header_len;
             case JUNIPER_LSQ_L3_PROTO_ISO:
-                isoclns_print(ndo, p, l2info.length, l2info.caplen);
+                isoclns_print(ndo, p, l2info.length);
                 return l2info.header_len;
             default:
                 break;
@@ -861,13 +861,13 @@
             ND_PRINT((ndo, "Bundle-ID %u, ", l2info.bundle));
         switch (l2info.proto) {
         case (LLCSAP_ISONS<<8 | LLCSAP_ISONS):
-            isoclns_print(ndo, p + 1, l2info.length - 1, l2info.caplen - 1);
+            isoclns_print(ndo, p + 1, l2info.length - 1);
             break;
         case (LLC_UI<<8 | NLPID_Q933):
         case (LLC_UI<<8 | NLPID_IP):
         case (LLC_UI<<8 | NLPID_IP6):
             /* pass IP{4,6} to the OSI layer for proper link-layer printing */
-            isoclns_print(ndo, p - 1, l2info.length + 1, l2info.caplen + 1);
+            isoclns_print(ndo, p - 1, l2info.length + 1);
             break;
         default:
             ND_PRINT((ndo, "unknown protocol 0x%04x, length %u", l2info.proto, l2info.length));
@@ -896,13 +896,13 @@
         switch (l2info.proto) {
         case (LLC_UI):
         case (LLC_UI<<8):
-            isoclns_print(ndo, p, l2info.length, l2info.caplen);
+            isoclns_print(ndo, p, l2info.length);
             break;
         case (LLC_UI<<8 | NLPID_Q933):
         case (LLC_UI<<8 | NLPID_IP):
         case (LLC_UI<<8 | NLPID_IP6):
             /* pass IP{4,6} to the OSI layer for proper link-layer printing */
-            isoclns_print(ndo, p - 1, l2info.length + 1, l2info.caplen + 1);
+            isoclns_print(ndo, p - 1, l2info.length + 1);
             break;
         default:
             ND_PRINT((ndo, "unknown protocol 0x%04x, length %u", l2info.proto, l2info.length));
@@ -949,7 +949,7 @@
         }
 
         if (p[0] == 0x03) { /* Cisco style NLPID encaps ? */
-            isoclns_print(ndo, p + 1, l2info.length - 1, l2info.caplen - 1);
+            isoclns_print(ndo, p + 1, l2info.length - 1);
             /* FIXME check if frame was recognized */
             return l2info.header_len;
         }
@@ -1004,7 +1004,7 @@
         }
 
         if (p[0] == 0x03) { /* Cisco style NLPID encaps ? */
-            isoclns_print(ndo, p + 1, l2info.length - 1, l2info.caplen - 1);
+            isoclns_print(ndo, p + 1, l2info.length - 1);
             /* FIXME check if frame was recognized */
             return l2info.header_len;
         }
```
