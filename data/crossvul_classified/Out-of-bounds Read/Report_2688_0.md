# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2688_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2688_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 61-101 of the vulnerable file.

        u_char  ar_pln;         /* length of protocol address */
        u_short ar_op;          /* one of: */
#define ARPOP_REQUEST   1       /* request to resolve address */
#define ARPOP_REPLY     2       /* response to previous request */
#define ARPOP_REVREQUEST 3      /* request protocol address given hardware */
#define ARPOP_REVREPLY  4       /* response giving protocol address */
#define ARPOP_INVREQUEST 8      /* request to identify peer */
#define ARPOP_INVREPLY  9       /* response identifying peer */
#define ARPOP_NAK       10      /* NAK - only valif for ATM ARP */

/*
 * The remaining fields are variable in size,
 * according to the sizes above.
 */
#ifdef COMMENT_ONLY
	u_char	ar_sha[];	/* sender hardware address */
	u_char	ar_spa[];	/* sender protocol address */
	u_char	ar_tha[];	/* target hardware address */
	u_char	ar_tpa[];	/* target protocol address */
#endif
#define ar_sha(ap)	(((const u_char *)((ap)+1))+0)
#define ar_spa(ap)	(((const u_char *)((ap)+1))+  (ap)->ar_hln)
#define ar_tha(ap)	(((const u_char *)((ap)+1))+  (ap)->ar_hln+(ap)->ar_pln)
#define ar_tpa(ap)	(((const u_char *)((ap)+1))+2*(ap)->ar_hln+(ap)->ar_pln)
};

#define ARP_HDRLEN	8

#define HRD(ap) EXTRACT_16BITS(&(ap)->ar_hrd)
#define HRD_LEN(ap) ((ap)->ar_hln)
#define PROTO_LEN(ap) ((ap)->ar_pln)
#define OP(ap)  EXTRACT_16BITS(&(ap)->ar_op)
#define PRO(ap) EXTRACT_16BITS(&(ap)->ar_pro)
#define SHA(ap) (ar_sha(ap))
#define SPA(ap) (ar_spa(ap))
#define THA(ap) (ar_tha(ap))
#define TPA(ap) (ar_tpa(ap))


static const struct tok arpop_values[] = {
    { ARPOP_REQUEST, "Request" },
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -78,7 +78,7 @@
 	u_char	ar_tha[];	/* target hardware address */
 	u_char	ar_tpa[];	/* target protocol address */
 #endif
-#define ar_sha(ap)	(((const u_char *)((ap)+1))+0)
+#define ar_sha(ap)	(((const u_char *)((ap)+1))+  0)
 #define ar_spa(ap)	(((const u_char *)((ap)+1))+  (ap)->ar_hln)
 #define ar_tha(ap)	(((const u_char *)((ap)+1))+  (ap)->ar_hln+(ap)->ar_pln)
 #define ar_tpa(ap)	(((const u_char *)((ap)+1))+2*(ap)->ar_hln+(ap)->ar_pln)
@@ -190,6 +190,30 @@
 }
 
 static void
+tpaddr_print_ip(netdissect_options *ndo,
+	        const struct arp_pkthdr *ap, u_short pro)
+{
+	if (pro != ETHERTYPE_IP && pro != ETHERTYPE_TRAIL)
+		ND_PRINT((ndo, "<wrong proto type>"));
+	else if (PROTO_LEN(ap) != 4)
+		ND_PRINT((ndo, "<wrong len>"));
+	else
+		ND_PRINT((ndo, "%s", ipaddr_string(ndo, TPA(ap))));
+}
+
+static void
+spaddr_print_ip(netdissect_options *ndo,
+	        const struct arp_pkthdr *ap, u_short pro)
+{
+	if (pro != ETHERTYPE_IP && pro != ETHERTYPE_TRAIL)
+		ND_PRINT((ndo, "<wrong proto type>"));
+	else if (PROTO_LEN(ap) != 4)
+		ND_PRINT((ndo, "<wrong len>"));
+	else
+		ND_PRINT((ndo, "%s", ipaddr_string(ndo, SPA(ap))));
+}
+
+static void
 atmarp_addr_print(netdissect_options *ndo,
 		  const u_char *ha, u_int ha_len, const u_char *srca,
     u_int srca_len)
@@ -202,6 +226,30 @@
 			ND_PRINT((ndo, ",%s",
 				  linkaddr_string(ndo, srca, LINKADDR_ATM, srca_len)));
 	}
+}
+
+static void
+atmarp_tpaddr_print(netdissect_options *ndo,
+		    const struct atmarp_pkthdr *ap, u_short pro)
+{
+	if (pro != ETHERTYPE_IP && pro != ETHERTYPE_TRAIL)
+		ND_PRINT((ndo, "<wrong proto type>"));
+	else if (ATMTPROTO_LEN(ap) != 4)
+		ND_PRINT((ndo, "<wrong tplen>"));
+	else
+		ND_PRINT((ndo, "%s", ipaddr_string(ndo, ATMTPA(ap))));
+}
+
+static void
+atmarp_spaddr_print(netdissect_options *ndo,
+		    const struct atmarp_pkthdr *ap, u_short pro)
+{
+	if (pro != ETHERTYPE_IP && pro != ETHERTYPE_TRAIL)
+		ND_PRINT((ndo, "<wrong proto type>"));
+	else if (ATMSPROTO_LEN(ap) != 4)
+		ND_PRINT((ndo, "<wrong splen>"));
+	else
+		ND_PRINT((ndo, "%s", ipaddr_string(ndo, ATMSPA(ap))));
 }
 
 static void
@@ -252,18 +300,21 @@
 	switch (op) {
 
 	case ARPOP_REQUEST:
-		ND_PRINT((ndo, "who-has %s", ipaddr_string(ndo, ATMTPA(ap))));
+		ND_PRINT((ndo, "who-has "));
+		atmarp_tpaddr_print(ndo, ap, pro);
 		if (ATMTHRD_LEN(ap) != 0) {
 			ND_PRINT((ndo, " ("));
 			atmarp_addr_print(ndo, ATMTHA(ap), ATMTHRD_LEN(ap),
 			    ATMTSA(ap), ATMTSLN(ap));
 			ND_PRINT((ndo, ")"));
 		}
-		ND_PRINT((ndo, "tell %s", ipaddr_string(ndo, ATMSPA(ap))));
+		ND_PRINT((ndo, " tell "));
+		atmarp_spaddr_print(ndo, ap, pro);
 		break;
 
 	case ARPOP_REPLY:
-		ND_PRINT((ndo, "%s is-at ", ipaddr_string(ndo, ATMSPA(ap))));
+		atmarp_spaddr_print(ndo, ap, pro);
+		ND_PRINT((ndo, " is-at "));
 		atmarp_addr_print(ndo, ATMSHA(ap), ATMSHRD_LEN(ap), ATMSSA(ap),
                                   ATMSSLN(ap));
 		break;
@@ -280,11 +331,13 @@
 	case ARPOP_INVREPLY:
 		atmarp_addr_print(ndo, ATMSHA(ap), ATMSHRD_LEN(ap), ATMSSA(ap),
 		    ATMSSLN(ap));
-		ND_PRINT((ndo, "at %s", ipaddr_string(ndo, ATMSPA(ap))));
+		ND_PRINT((ndo, "at "));
+		atmarp_spaddr_print(ndo, ap, pro);
 		break;
 
 	case ARPOP_NAK:
-		ND_PRINT((ndo, "for %s", ipaddr_string(ndo, ATMSPA(ap))));
+		ND_PRINT((ndo, "for "));
+		atmarp_spaddr_print(ndo, ap, pro);
 		break;
 
 	default:
@@ -332,7 +385,7 @@
             break;
 	}
 
-	if (!ND_TTEST2(*ar_tpa(ap), PROTO_LEN(ap))) {
+	if (!ND_TTEST2(*TPA(ap), PROTO_LEN(ap))) {
 		ND_PRINT((ndo, "%s", tstr));
 		ND_DEFAULTPRINT((const u_char *)ap, length);
 		return;
@@ -367,16 +420,18 @@
 	switch (op) {
 
 	case ARPOP_REQUEST:
-		ND_PRINT((ndo, "who-has %s", ipaddr_string(ndo, TPA(ap))));
+		ND_PRINT((ndo, "who-has "));
+		tpaddr_print_ip(ndo, ap, pro);
 		if (isnonzero((const u_char *)THA(ap), HRD_LEN(ap)))
 			ND_PRINT((ndo, " (%s)",
 				  linkaddr_string(ndo, THA(ap), linkaddr, HRD_LEN(ap))));
-		ND_PRINT((ndo, " tell %s", ipaddr_string(ndo, SPA(ap))));
+		ND_PRINT((ndo, " tell "));
+		spaddr_print_ip(ndo, ap, pro);
 		break;
 
 	case ARPOP_REPLY:
-		ND_PRINT((ndo, "%s is-at %s",
-                          ipaddr_string(ndo, SPA(ap)),
+		spaddr_print_ip(ndo, ap, pro);
+		ND_PRINT((ndo, " is-at %s",
                           linkaddr_string(ndo, SHA(ap), linkaddr, HRD_LEN(ap))));
 		break;
 
@@ -387,9 +442,9 @@
 		break;
 
 	case ARPOP_REVREPLY:
-		ND_PRINT((ndo, "%s at %s",
-			  linkaddr_string(ndo, THA(ap), linkaddr, HRD_LEN(ap)),
-			  ipaddr_string(ndo, TPA(ap))));
+		ND_PRINT((ndo, "%s at ",
+			  linkaddr_string(ndo, THA(ap), linkaddr, HRD_LEN(ap))));
+		tpaddr_print_ip(ndo, ap, pro);
 		break;
 
 	case ARPOP_INVREQUEST:
@@ -399,9 +454,9 @@
 		break;
 
 	case ARPOP_INVREPLY:
-		ND_PRINT((ndo,"%s at %s",
-			  linkaddr_string(ndo, SHA(ap), linkaddr, HRD_LEN(ap)),
-			  ipaddr_string(ndo, SPA(ap))));
+		ND_PRINT((ndo,"%s at ",
+			  linkaddr_string(ndo, SHA(ap), linkaddr, HRD_LEN(ap))));
+		spaddr_print_ip(ndo, ap, pro);
 		break;
 
 	default:
```
