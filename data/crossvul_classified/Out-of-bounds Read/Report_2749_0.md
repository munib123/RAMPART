# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2749_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2749_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1296-1336 of the vulnerable file.

	return cp;
trunc:
	ND_PRINT((ndo," [|%s]", NPSTR(ISAKMP_NPTYPE_T)));
	return NULL;
}

static const u_char *
ikev1_ke_print(netdissect_options *ndo, u_char tpay _U_,
	       const struct isakmp_gen *ext, u_int item_len _U_,
	       const u_char *ep _U_, uint32_t phase _U_, uint32_t doi _U_,
	       uint32_t proto _U_, int depth _U_)
{
	struct isakmp_gen e;

	ND_PRINT((ndo,"%s:", NPSTR(ISAKMP_NPTYPE_KE)));

	ND_TCHECK(*ext);
	UNALIGNED_MEMCPY(&e, ext, sizeof(e));
	ND_PRINT((ndo," key len=%d", ntohs(e.len) - 4));
	if (2 < ndo->ndo_vflag && 4 < ntohs(e.len)) {
		ND_PRINT((ndo," "));
		if (!rawprint(ndo, (const uint8_t *)(ext + 1), ntohs(e.len) - 4))
			goto trunc;
	}
	return (const u_char *)ext + ntohs(e.len);
trunc:
	ND_PRINT((ndo," [|%s]", NPSTR(ISAKMP_NPTYPE_KE)));
	return NULL;
}

static const u_char *
ikev1_id_print(netdissect_options *ndo, u_char tpay _U_,
	       const struct isakmp_gen *ext, u_int item_len,
	       const u_char *ep _U_, uint32_t phase, uint32_t doi _U_,
	       uint32_t proto _U_, int depth _U_)
{
#define USE_IPSECDOI_IN_PHASE1	1
	const struct ikev1_pl_id *p;
	struct ikev1_pl_id id;
	static const char *idtypestr[] = {
		"IPv4", "IPv4net", "IPv6", "IPv6net",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1313,6 +1313,7 @@
 	UNALIGNED_MEMCPY(&e, ext, sizeof(e));
 	ND_PRINT((ndo," key len=%d", ntohs(e.len) - 4));
 	if (2 < ndo->ndo_vflag && 4 < ntohs(e.len)) {
+		/* Print the entire payload in hex */
 		ND_PRINT((ndo," "));
 		if (!rawprint(ndo, (const uint8_t *)(ext + 1), ntohs(e.len) - 4))
 			goto trunc;
@@ -1515,6 +1516,7 @@
 	ND_PRINT((ndo," len=%d", item_len - 4));
 	ND_PRINT((ndo," type=%s", STR_OR_ID((cert.encode), certstr)));
 	if (2 < ndo->ndo_vflag && 4 < item_len) {
+		/* Print the entire payload in hex */
 		ND_PRINT((ndo," "));
 		if (!rawprint(ndo, (const uint8_t *)(ext + 1), item_len - 4))
 			goto trunc;
@@ -1547,6 +1549,7 @@
 	ND_PRINT((ndo," len=%d", item_len - 4));
 	ND_PRINT((ndo," type=%s", STR_OR_ID((cert.encode), certstr)));
 	if (2 < ndo->ndo_vflag && 4 < item_len) {
+		/* Print the entire payload in hex */
 		ND_PRINT((ndo," "));
 		if (!rawprint(ndo, (const uint8_t *)(ext + 1), item_len - 4))
 			goto trunc;
@@ -1571,6 +1574,7 @@
 	UNALIGNED_MEMCPY(&e, ext, sizeof(e));
 	ND_PRINT((ndo," len=%d", ntohs(e.len) - 4));
 	if (2 < ndo->ndo_vflag && 4 < ntohs(e.len)) {
+		/* Print the entire payload in hex */
 		ND_PRINT((ndo," "));
 		if (!rawprint(ndo, (const uint8_t *)(ext + 1), ntohs(e.len) - 4))
 			goto trunc;
@@ -1595,6 +1599,7 @@
 	UNALIGNED_MEMCPY(&e, ext, sizeof(e));
 	ND_PRINT((ndo," len=%d", ntohs(e.len) - 4));
 	if (2 < ndo->ndo_vflag && 4 < ntohs(e.len)) {
+		/* Print the entire payload in hex */
 		ND_PRINT((ndo," "));
 		if (!rawprint(ndo, (const uint8_t *)(ext + 1), ntohs(e.len) - 4))
 			goto trunc;
@@ -1850,6 +1855,7 @@
 	UNALIGNED_MEMCPY(&e, ext, sizeof(e));
 	ND_PRINT((ndo," len=%d", ntohs(e.len) - 4));
 	if (2 < ndo->ndo_vflag && 4 < ntohs(e.len)) {
+		/* Print the entire payload in hex */
 		ND_PRINT((ndo," "));
 		if (!rawprint(ndo, (const uint8_t *)(ext + 1), ntohs(e.len) - 4))
 			goto trunc;
@@ -1884,6 +1890,7 @@
 
 	ND_PRINT((ndo," len=%d", ntohs(e.len) - 4));
 	if (2 < ndo->ndo_vflag && 4 < ntohs(e.len)) {
+		/* Print the entire payload in hex */
 		ND_PRINT((ndo," "));
 		if (!rawprint(ndo, (const uint8_t *)(ext + 1), ntohs(e.len) - 4))
 			goto trunc;
@@ -2022,7 +2029,6 @@
 		if (prop_length < sizeof(*ext))
 			goto toolong;
 		ND_TCHECK(*ext);
-
 		UNALIGNED_MEMCPY(&e, ext, sizeof(e));
 
 		/*
@@ -2109,7 +2115,6 @@
 		if (sa_length < sizeof(*ext))
 			goto toolong;
 		ND_TCHECK(*ext);
-
 		UNALIGNED_MEMCPY(&e, ext, sizeof(e));
 
 		/*
@@ -2170,7 +2175,7 @@
 	const struct ikev2_ke *k;
 
 	k = (const struct ikev2_ke *)ext;
-	ND_TCHECK(*ext);
+	ND_TCHECK(*k);
 	UNALIGNED_MEMCPY(&ke, ext, sizeof(ke));
 	ikev2_pay_print(ndo, NPSTR(tpay), ke.h.critical);
 
@@ -2195,12 +2200,14 @@
 		uint32_t phase _U_, uint32_t doi _U_,
 		uint32_t proto _U_, int depth _U_)
 {
+	const struct ikev2_id *idp;
 	struct ikev2_id id;
 	int id_len, idtype_len, i;
 	unsigned int dumpascii, dumphex;
 	const unsigned char *typedata;
 
-	ND_TCHECK(*ext);
+	idp = (const struct ikev2_id *)ext;
+	ND_TCHECK(*idp);
 	UNALIGNED_MEMCPY(&id, ext, sizeof(id));
 	ikev2_pay_print(ndo, NPSTR(tpay), id.h.critical);
 
@@ -2208,6 +2215,7 @@
 
 	ND_PRINT((ndo," len=%d", id_len - 4));
 	if (2 < ndo->ndo_vflag && 4 < id_len) {
+		/* Print the entire payload in hex */
 		ND_PRINT((ndo," "));
 		if (!rawprint(ndo, (const uint8_t *)(ext + 1), id_len - 4))
 			goto trunc;
@@ -2303,7 +2311,7 @@
 	const u_char *authdata = (const u_char*)ext + sizeof(a);
 	unsigned int len;
 
-	ND_TCHECK(*ext);
+	ND_TCHECK2(*ext, sizeof(a));
 	UNALIGNED_MEMCPY(&a, ext, sizeof(a));
 	ikev2_pay_print(ndo, NPSTR(tpay), a.h.critical);
 	len = ntohs(a.h.len);
@@ -2599,6 +2607,7 @@
 		else ND_PRINT((ndo, "."));
 	}
 	if (2 < ndo->ndo_vflag && 4 < len) {
+		/* Print the entire payload in hex */
 		ND_PRINT((ndo," "));
 		if (!rawprint(ndo, (const uint8_t *)(ext + 1), ntohs(e.len) - 4))
 			goto trunc;
@@ -2764,7 +2773,6 @@
 
 	while (np) {
 		ND_TCHECK(*ext);
-
 		UNALIGNED_MEMCPY(&e, ext, sizeof(e));
 
 		ND_TCHECK2(*ext, ntohs(e.len));
@@ -2932,7 +2940,6 @@
 	cp = (const u_char *)ext;
 	while (np) {
 		ND_TCHECK(*ext);
-
 		UNALIGNED_MEMCPY(&e, ext, sizeof(e));
 
 		ND_TCHECK2(*ext, ntohs(e.len));
```
