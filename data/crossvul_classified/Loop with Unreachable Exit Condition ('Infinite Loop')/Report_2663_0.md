# CrossVul Fix Pair: Loop with Unreachable Exit Condition ('Infinite Loop') in c
**Pair ID:** 2663_0
**Vulnerability Class:** Loop with Unreachable Exit Condition ('Infinite Loop')
**CWE:** CWE-835
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2663_0`)

## Vulnerability Information & PoC

## Description
Loop with Unreachable Exit Condition ('Infinite Loop') - If the loop can be influenced by an attacker, this weakness could allow attackers to consume excessive resources such as CPU or memory.

## Vulnerable Code
```c
Lines 411-451 of the vulnerable file.

	IV2_NOTIFY_INVALID_SELECTORS                       =39,
	IV2_NOTIFY_INITIAL_CONTACT                         =16384,
	IV2_NOTIFY_SET_WINDOW_SIZE                         =16385,
	IV2_NOTIFY_ADDITIONAL_TS_POSSIBLE                  =16386,
	IV2_NOTIFY_IPCOMP_SUPPORTED                        =16387,
	IV2_NOTIFY_NAT_DETECTION_SOURCE_IP                 =16388,
	IV2_NOTIFY_NAT_DETECTION_DESTINATION_IP            =16389,
	IV2_NOTIFY_COOKIE                                  =16390,
	IV2_NOTIFY_USE_TRANSPORT_MODE                      =16391,
	IV2_NOTIFY_HTTP_CERT_LOOKUP_SUPPORTED              =16392,
	IV2_NOTIFY_REKEY_SA                                =16393,
	IV2_NOTIFY_ESP_TFC_PADDING_NOT_SUPPORTED           =16394,
	IV2_NOTIFY_NON_FIRST_FRAGMENTS_ALSO                =16395
};

struct notify_messages {
	uint16_t type;
	char     *msg;
};

/* 3.8 Notification Payload */
struct ikev2_auth {
	struct isakmp_gen h;
	uint8_t  auth_method;  /* Protocol-ID */
	uint8_t  reserved[3];
	/* authentication data */
};

enum ikev2_auth_type {
	IV2_RSA_SIG = 1,
	IV2_SHARED  = 2,
	IV2_DSS_SIG = 3
};

/* refer to RFC 2409 */

#if 0
/* isakmp sa structure */
struct oakley_sa {
	uint8_t  proto_id;            /* OAKLEY */
	vchar_t   *spi;                /* spi */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -428,7 +428,7 @@
 	char     *msg;
 };
 
-/* 3.8 Notification Payload */
+/* 3.8 Authentication Payload */
 struct ikev2_auth {
 	struct isakmp_gen h;
 	uint8_t  auth_method;  /* Protocol-ID */
@@ -1590,15 +1590,20 @@
 
 	ND_TCHECK(*ext);
 	UNALIGNED_MEMCPY(&e, ext, sizeof(e));
-	ND_PRINT((ndo," n len=%d", ntohs(e.len) - 4));
-	if (2 < ndo->ndo_vflag && 4 < ntohs(e.len)) {
-		ND_PRINT((ndo," "));
-		if (!rawprint(ndo, (const uint8_t *)(ext + 1), ntohs(e.len) - 4))
-			goto trunc;
-	} else if (1 < ndo->ndo_vflag && 4 < ntohs(e.len)) {
-		ND_PRINT((ndo," "));
-		if (!ike_show_somedata(ndo, (const u_char *)(const uint8_t *)(ext + 1), ep))
-			goto trunc;
+	/*
+	 * Our caller has ensured that the length is >= 4.
+	 */
+	ND_PRINT((ndo," n len=%u", ntohs(e.len) - 4));
+	if (ntohs(e.len) > 4) {
+		if (ndo->ndo_vflag > 2) {
+			ND_PRINT((ndo, " "));
+			if (!rawprint(ndo, (const uint8_t *)(ext + 1), ntohs(e.len) - 4))
+				goto trunc;
+		} else if (ndo->ndo_vflag > 1) {
+			ND_PRINT((ndo, " "));
+			if (!ike_show_somedata(ndo, (const u_char *)(ext + 1), ep))
+				goto trunc;
+		}
 	}
 	return (const u_char *)ext + ntohs(e.len);
 trunc:
@@ -1609,8 +1614,8 @@
 static const u_char *
 ikev1_n_print(netdissect_options *ndo, u_char tpay _U_,
 	      const struct isakmp_gen *ext, u_int item_len,
-	      const u_char *ep, uint32_t phase, uint32_t doi0 _U_,
-	      uint32_t proto0 _U_, int depth)
+	      const u_char *ep, uint32_t phase _U_, uint32_t doi0 _U_,
+	      uint32_t proto0 _U_, int depth _U_)
 {
 	const struct ikev1_pl_n *p;
 	struct ikev1_pl_n n;
@@ -1712,35 +1717,41 @@
 	ep2 = (const u_char *)p + item_len;
 
 	if (cp < ep) {
-		ND_PRINT((ndo," orig=("));
 		switch (ntohs(n.type)) {
 		case IPSECDOI_NTYPE_RESPONDER_LIFETIME:
 		    {
 			const struct attrmap *map = oakley_t_map;
 			size_t nmap = sizeof(oakley_t_map)/sizeof(oakley_t_map[0]);
+			ND_PRINT((ndo," attrs=("));
 			while (cp < ep && cp < ep2) {
 				cp = ikev1_attrmap_print(ndo, cp,
 					(ep < ep2) ? ep : ep2, map, nmap);
 			}
+			ND_PRINT((ndo,")"));
 			break;
 		    }
 		case IPSECDOI_NTYPE_REPLAY_STATUS:
+			ND_PRINT((ndo," status=("));
 			ND_PRINT((ndo,"replay detection %sabled",
 				  EXTRACT_32BITS(cp) ? "en" : "dis"));
-			break;
-		case ISAKMP_NTYPE_NO_PROPOSAL_CHOSEN:
-			if (ikev1_sub_print(ndo, ISAKMP_NPTYPE_SA,
-					    (const struct isakmp_gen *)cp, ep, phase, doi, proto,
-					    depth) == NULL)
-				return NULL;
+			ND_PRINT((ndo,")"));
 			break;
 		default:
-			/* NULL is dummy */
-			isakmp_print(ndo, cp,
-				     item_len - sizeof(*p) - n.spi_size,
-				     NULL);
+			/*
+			 * XXX - fill in more types here; see, for example,
+			 * draft-ietf-ipsec-notifymsg-04.
+			 */
+			if (ndo->ndo_vflag > 3) {
+				ND_PRINT((ndo," data=("));
+				if (!rawprint(ndo, (const uint8_t *)(cp), ep - cp))
+					goto trunc;
+				ND_PRINT((ndo,")"));
+			} else {
+				if (!ike_show_somedata(ndo, cp, ep))
+					goto trunc;
+			}
+			break;
 		}
-		ND_PRINT((ndo,")"));
 	}
 	return (const u_char *)ext + item_len;
 trunc:
@@ -2264,16 +2275,21 @@
 	ikev2_pay_print(ndo, NPSTR(tpay), a.h.critical);
 	len = ntohs(a.h.len);
 
-	ND_PRINT((ndo," len=%d method=%s", len-4,
+	/*
+	 * Our caller has ensured that the length is >= 4.
+	 */
+	ND_PRINT((ndo," len=%u method=%s", len-4,
 		  STR_OR_ID(a.auth_method, v2_auth)));
-
-	if (1 < ndo->ndo_vflag && 4 < len) {
-		ND_PRINT((ndo," authdata=("));
-		if (!rawprint(ndo, (const uint8_t *)authdata, len - sizeof(a)))
-			goto trunc;
-		ND_PRINT((ndo,") "));
-	} else if(ndo->ndo_vflag && 4 < len) {
-		if(!ike_show_somedata(ndo, authdata, ep)) goto trunc;
+	if (len > 4) {
+		if (ndo->ndo_vflag > 1) {
+			ND_PRINT((ndo, " authdata=("));
+			if (!rawprint(ndo, (const uint8_t *)authdata, len - sizeof(a)))
+				goto trunc;
+			ND_PRINT((ndo, ") "));
+		} else if (ndo->ndo_vflag) {
+			if (!ike_show_somedata(ndo, authdata, ep))
+				goto trunc;
+		}
 	}
 
 	return (const u_char *)ext + len;
@@ -2322,7 +2338,7 @@
 	const struct ikev2_n *p;
 	struct ikev2_n n;
 	const u_char *cp;
-	u_char showspi, showdata, showsomedata;
+	u_char showspi, showsomedata;
 	const char *notify_name;
 	uint32_t type;
 
@@ -2332,7 +2348,6 @@
 	ikev2_pay_print(ndo, NPSTR(ISAKMP_NPTYPE_N), n.h.critical);
 
 	showspi = 1;
-	showdata = 0;
 	showsomedata=0;
 	notify_name=NULL;
 
@@ -2446,7 +2461,6 @@
 		notify_name = "cookie";
 		showspi = 1;
 		showsomedata= 1;
-		showdata= 0;
 		break;
 
 	case IV2_NOTIFY_USE_TRANSPORT_MODE:
@@ -2499,19 +2513,17 @@
 
 	cp = (const u_char *)(p + 1) + n.spi_size;
 
-	if(3 < ndo->ndo_vflag) {
-		showdata = 1;
-	}
-
-	if ((showdata || (showsomedata && ep-cp < 30)) && cp < ep) {
-		ND_PRINT((ndo," data=("));
-		if (!rawprint(ndo, (const uint8_t *)(cp), ep - cp))
-			goto trunc;
-
-		ND_PRINT((ndo,")"));
-
-	} else if(showsomedata && cp < ep) {
-		if(!ike_show_somedata(ndo, cp, ep)) goto trunc;
+	if (cp < ep) {
+		if (ndo->ndo_vflag > 3 || (showsomedata && ep-cp < 30)) {
+			ND_PRINT((ndo," data=("));
+			if (!rawprint(ndo, (const uint8_t *)(cp), ep - cp))
+				goto trunc;
+
+			ND_PRINT((ndo,")"));
+		} else if (showsomedata) {
+			if (!ike_show_somedata(ndo, cp, ep))
+				goto trunc;
+		}
 	}
 
 	return (const u_char *)ext + item_len;
@@ -3091,7 +3103,3 @@
  * c-basic-offset: 8
  * End:
  */
-
-
-
-
```
