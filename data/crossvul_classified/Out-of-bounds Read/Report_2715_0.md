# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2715_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2715_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 895-935 of the vulnerable file.

	if(!rawprint(ndo, (const uint8_t *)(cp), len)) goto trunc;
	ND_PRINT((ndo, "..."));
	if(elen) {
		if(!rawprint(ndo, (const uint8_t *)(end), elen)) goto trunc;
	}
	ND_PRINT((ndo,")"));
	return 1;

trunc:
	return 0;
}

struct attrmap {
	const char *type;
	u_int nvalue;
	const char *value[30];	/*XXX*/
};

static const u_char *
ikev1_attrmap_print(netdissect_options *ndo,
		    const u_char *p, const u_char *ep,
		    const struct attrmap *map, size_t nmap)
{
	int totlen;
	uint32_t t, v;

	if (p[0] & 0x80)
		totlen = 4;
	else
		totlen = 4 + EXTRACT_16BITS(&p[2]);
	if (ep < p + totlen) {
		ND_PRINT((ndo,"[|attr]"));
		return ep + 1;
	}

	ND_PRINT((ndo,"("));
	t = EXTRACT_16BITS(&p[0]) & 0x7fff;
	if (map && t < nmap && map[t].type)
		ND_PRINT((ndo,"type=%s ", map[t].type));
	else
		ND_PRINT((ndo,"type=#%d ", t));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -912,21 +912,25 @@
 
 static const u_char *
 ikev1_attrmap_print(netdissect_options *ndo,
-		    const u_char *p, const u_char *ep,
+		    const u_char *p, const u_char *ep2,
 		    const struct attrmap *map, size_t nmap)
 {
 	int totlen;
 	uint32_t t, v;
 
+	ND_TCHECK(p[0]);
 	if (p[0] & 0x80)
 		totlen = 4;
-	else
+	else {
+		ND_TCHECK_16BITS(&p[2]);
 		totlen = 4 + EXTRACT_16BITS(&p[2]);
-	if (ep < p + totlen) {
+	}
+	if (ep2 < p + totlen) {
 		ND_PRINT((ndo,"[|attr]"));
-		return ep + 1;
-	}
-
+		return ep2 + 1;
+	}
+
+	ND_TCHECK_16BITS(&p[0]);
 	ND_PRINT((ndo,"("));
 	t = EXTRACT_16BITS(&p[0]) & 0x7fff;
 	if (map && t < nmap && map[t].type)
@@ -935,47 +939,71 @@
 		ND_PRINT((ndo,"type=#%d ", t));
 	if (p[0] & 0x80) {
 		ND_PRINT((ndo,"value="));
+		ND_TCHECK_16BITS(&p[2]);
 		v = EXTRACT_16BITS(&p[2]);
 		if (map && t < nmap && v < map[t].nvalue && map[t].value[v])
 			ND_PRINT((ndo,"%s", map[t].value[v]));
-		else
-			rawprint(ndo, (const uint8_t *)&p[2], 2);
+		else {
+			if (!rawprint(ndo, (const uint8_t *)&p[2], 2)) {
+				ND_PRINT((ndo,")"));
+				goto trunc;
+			}
+		}
 	} else {
-		ND_PRINT((ndo,"len=%d value=", EXTRACT_16BITS(&p[2])));
-		rawprint(ndo, (const uint8_t *)&p[4], EXTRACT_16BITS(&p[2]));
+		ND_PRINT((ndo,"len=%d value=", totlen - 4));
+		if (!rawprint(ndo, (const uint8_t *)&p[4], totlen - 4)) {
+			ND_PRINT((ndo,")"));
+			goto trunc;
+		}
 	}
 	ND_PRINT((ndo,")"));
 	return p + totlen;
-}
-
-static const u_char *
-ikev1_attr_print(netdissect_options *ndo, const u_char *p, const u_char *ep)
+
+trunc:
+	return NULL;
+}
+
+static const u_char *
+ikev1_attr_print(netdissect_options *ndo, const u_char *p, const u_char *ep2)
 {
 	int totlen;
 	uint32_t t;
 
+	ND_TCHECK(p[0]);
 	if (p[0] & 0x80)
 		totlen = 4;
-	else
+	else {
+		ND_TCHECK_16BITS(&p[2]);
 		totlen = 4 + EXTRACT_16BITS(&p[2]);
-	if (ep < p + totlen) {
+	}
+	if (ep2 < p + totlen) {
 		ND_PRINT((ndo,"[|attr]"));
-		return ep + 1;
-	}
-
+		return ep2 + 1;
+	}
+
+	ND_TCHECK_16BITS(&p[0]);
 	ND_PRINT((ndo,"("));
 	t = EXTRACT_16BITS(&p[0]) & 0x7fff;
 	ND_PRINT((ndo,"type=#%d ", t));
 	if (p[0] & 0x80) {
 		ND_PRINT((ndo,"value="));
 		t = p[2];
-		rawprint(ndo, (const uint8_t *)&p[2], 2);
+		if (!rawprint(ndo, (const uint8_t *)&p[2], 2)) {
+			ND_PRINT((ndo,")"));
+			goto trunc;
+		}
 	} else {
-		ND_PRINT((ndo,"len=%d value=", EXTRACT_16BITS(&p[2])));
-		rawprint(ndo, (const uint8_t *)&p[4], EXTRACT_16BITS(&p[2]));
+		ND_PRINT((ndo,"len=%d value=", totlen - 4));
+		if (!rawprint(ndo, (const uint8_t *)&p[4], totlen - 4)) {
+			ND_PRINT((ndo,")"));
+			goto trunc;
+		}
 	}
 	ND_PRINT((ndo,")"));
 	return p + totlen;
+
+trunc:
+	return NULL;
 }
 
 static const u_char *
@@ -1256,11 +1284,12 @@
 	cp = (const u_char *)(p + 1);
 	ep2 = (const u_char *)p + item_len;
 	while (cp < ep && cp < ep2) {
-		if (map && nmap) {
-			cp = ikev1_attrmap_print(ndo, cp, (ep < ep2) ? ep : ep2,
-				map, nmap);
-		} else
-			cp = ikev1_attr_print(ndo, cp, (ep < ep2) ? ep : ep2);
+		if (map && nmap)
+			cp = ikev1_attrmap_print(ndo, cp, ep2, map, nmap);
+		else
+			cp = ikev1_attr_print(ndo, cp, ep2);
+		if (cp == NULL)
+			goto trunc;
 	}
 	if (ep < ep2)
 		ND_PRINT((ndo,"..."));
@@ -1724,8 +1753,11 @@
 			size_t nmap = sizeof(oakley_t_map)/sizeof(oakley_t_map[0]);
 			ND_PRINT((ndo," attrs=("));
 			while (cp < ep && cp < ep2) {
-				cp = ikev1_attrmap_print(ndo, cp,
-					(ep < ep2) ? ep : ep2, map, nmap);
+				cp = ikev1_attrmap_print(ndo, cp, ep2, map, nmap);
+				if (cp == NULL) {
+					ND_PRINT((ndo,")"));
+					goto trunc;
+				}
 			}
 			ND_PRINT((ndo,")"));
 			break;
@@ -1926,10 +1958,11 @@
 	ep2 = (const u_char *)p + item_len;
 	while (cp < ep && cp < ep2) {
 		if (map && nmap) {
-			cp = ikev1_attrmap_print(ndo, cp, (ep < ep2) ? ep : ep2,
-				map, nmap);
+			cp = ikev1_attrmap_print(ndo, cp, ep2, map, nmap);
 		} else
-			cp = ikev1_attr_print(ndo, cp, (ep < ep2) ? ep : ep2);
+			cp = ikev1_attr_print(ndo, cp, ep2);
+		if (cp == NULL)
+			goto trunc;
 	}
 	if (ep < ep2)
 		ND_PRINT((ndo,"..."));
```
