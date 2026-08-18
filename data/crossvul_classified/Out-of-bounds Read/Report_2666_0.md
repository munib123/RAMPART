# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2666_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2666_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 455-495 of the vulnerable file.

                   const struct pcap_pkthdr *h, register const u_char *p)
{
        struct juniper_l2info_t l2info;
        struct juniper_ggsn_header {
            uint8_t svc_id;
            uint8_t flags_len;
            uint8_t proto;
            uint8_t flags;
            uint8_t vlan_id[2];
            uint8_t res[2];
        };
        const struct juniper_ggsn_header *gh;

        l2info.pictype = DLT_JUNIPER_GGSN;
        if (juniper_parse_header(ndo, p, h, &l2info) == 0)
            return l2info.header_len;

        p+=l2info.header_len;
        gh = (struct juniper_ggsn_header *)&l2info.cookie;

        if (ndo->ndo_eflag) {
            ND_PRINT((ndo, "proto %s (%u), vlan %u: ",
                   tok2str(juniper_protocol_values,"Unknown",gh->proto),
                   gh->proto,
                   EXTRACT_16BITS(&gh->vlan_id[0])));
        }

        switch (gh->proto) {
        case JUNIPER_PROTO_IPV4:
            ip_print(ndo, p, l2info.length);
            break;
        case JUNIPER_PROTO_IPV6:
            ip6_print(ndo, p, l2info.length);
            break;
        default:
            if (!ndo->ndo_eflag)
                ND_PRINT((ndo, "unknown GGSN proto (%u)", gh->proto));
        }

        return l2info.header_len;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -472,6 +472,7 @@
         p+=l2info.header_len;
         gh = (struct juniper_ggsn_header *)&l2info.cookie;
 
+        ND_TCHECK(*gh);
         if (ndo->ndo_eflag) {
             ND_PRINT((ndo, "proto %s (%u), vlan %u: ",
                    tok2str(juniper_protocol_values,"Unknown",gh->proto),
@@ -492,6 +493,10 @@
         }
 
         return l2info.header_len;
+
+trunc:
+	ND_PRINT((ndo, "[|juniper_services]"));
+	return l2info.header_len;
 }
 #endif
 
@@ -519,6 +524,7 @@
         p+=l2info.header_len;
         ih = (const struct juniper_ipsec_header *)p;
 
+        ND_TCHECK(*ih);
         switch (ih->type) {
         case JUNIPER_IPSEC_O_ESP_ENCRYPT_ESP_AUTHEN_TYPE:
         case JUNIPER_IPSEC_O_ESP_ENCRYPT_AH_AUTHEN_TYPE:
@@ -564,6 +570,10 @@
 
         ip_print(ndo, p, l2info.length);
         return l2info.header_len;
+
+trunc:
+	ND_PRINT((ndo, "[|juniper_services]"));
+	return l2info.header_len;
 }
 #endif
 
@@ -588,6 +598,7 @@
         p+=l2info.header_len;
         mh = (const struct juniper_monitor_header *)p;
 
+        ND_TCHECK(*mh);
         if (ndo->ndo_eflag)
             ND_PRINT((ndo, "service-id %u, iif %u, pkt-type %u: ",
                    EXTRACT_32BITS(&mh->service_id),
@@ -598,6 +609,10 @@
         ip_heuristic_guess (ndo, p, l2info.length);
 
         return l2info.header_len;
+
+trunc:
+	ND_PRINT((ndo, "[|juniper_services]"));
+	return l2info.header_len;
 }
 #endif
 
@@ -622,6 +637,7 @@
         p+=l2info.header_len;
         sh = (const struct juniper_services_header *)p;
 
+        ND_TCHECK(*sh);
         if (ndo->ndo_eflag)
             ND_PRINT((ndo, "service-id %u flags 0x%02x service-set-id 0x%04x iif %u: ",
                    sh->svc_id,
@@ -633,6 +649,10 @@
         ip_heuristic_guess (ndo, p, l2info.length);
 
         return l2info.header_len;
+
+trunc:
+	ND_PRINT((ndo, "[|juniper_services]"));
+	return l2info.header_len;
 }
 #endif
 
@@ -740,6 +760,7 @@
 
         p+=l2info.header_len;
 
+        ND_TCHECK2(p[0], 2);
         extracted_ethertype = EXTRACT_16BITS(p);
         /* this DLT contains nothing but raw PPPoE frames,
          * prepended with a type field*/
@@ -752,6 +773,10 @@
             ND_PRINT((ndo, "unknown ethertype 0x%04x", extracted_ethertype));
 
         return l2info.header_len;
+
+trunc:
+	ND_PRINT((ndo, "[|juniper_pppoe_atm]"));
+	return l2info.header_len;
 }
 #endif
 
@@ -940,6 +965,7 @@
             return l2info.header_len;
         }
 
+        ND_TCHECK2(p[0], 3);
         if (EXTRACT_24BITS(p) == 0xfefe03 || /* NLPID encaps ? */
             EXTRACT_24BITS(p) == 0xaaaa03) { /* SNAP encaps ? */
 
@@ -957,6 +983,10 @@
         if (ip_heuristic_guess(ndo, p, l2info.length) != 0) /* last try - vcmux encaps ? */
             return l2info.header_len;
 
+	return l2info.header_len;
+
+trunc:
+	ND_PRINT((ndo, "[|juniper_atm1]"));
 	return l2info.header_len;
 }
 #endif
@@ -989,6 +1019,7 @@
             return l2info.header_len;
         }
 
+        ND_TCHECK2(p[0], 3);
         if (EXTRACT_24BITS(p) == 0xfefe03 || /* NLPID encaps ? */
             EXTRACT_24BITS(p) == 0xaaaa03) { /* SNAP encaps ? */
 
@@ -1015,6 +1046,10 @@
         if (ip_heuristic_guess(ndo, p, l2info.length) != 0) /* last try - vcmux encaps ? */
             return l2info.header_len;
 
+	return l2info.header_len;
+
+trunc:
+	ND_PRINT((ndo, "[|juniper_atm2]"));
 	return l2info.header_len;
 }
 #endif
@@ -1280,6 +1315,7 @@
     l2info->caplen -= l2info->header_len;
 
     /* search through the cookie table and copy values matching for our PIC type */
+    ND_TCHECK(p[0]);
     while (lp->s != NULL) {
         if (lp->pictype == l2info->pictype) {
 
@@ -1360,6 +1396,7 @@
     case DLT_JUNIPER_MLFR:
         switch (l2info->cookie_type) {
         case LS_COOKIE_ID:
+            ND_TCHECK2(p[0], 2);
             l2info->bundle = l2info->cookie[1];
             l2info->proto = EXTRACT_16BITS(p);
             l2info->header_len += 2;
@@ -1383,6 +1420,7 @@
     case DLT_JUNIPER_MFR:
         switch (l2info->cookie_type) {
         case LS_COOKIE_ID:
+            ND_TCHECK2(p[0], 2);
             l2info->bundle = l2info->cookie[1];
             l2info->proto = EXTRACT_16BITS(p);
             l2info->header_len += 2;
```
