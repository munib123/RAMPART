# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2713_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2713_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 151-191 of the vulnerable file.

	} ph;
	struct cksum_vec vec[2];

	/* pseudo-header.. */
	ph.len = htons((uint16_t)len);
	ph.mbz = 0;
	ph.proto = next_proto;
	UNALIGNED_MEMCPY(&ph.src, &ip->ip_src, sizeof(uint32_t));
	if (IP_HL(ip) == 5)
		UNALIGNED_MEMCPY(&ph.dst, &ip->ip_dst, sizeof(uint32_t));
	else
		ph.dst = ip_finddst(ndo, ip);

	vec[0].ptr = (const uint8_t *)(void *)&ph;
	vec[0].len = sizeof(ph);
	vec[1].ptr = data;
	vec[1].len = covlen;
	return (in_cksum(vec, 2));
}

static void
ip_printts(netdissect_options *ndo,
           register const u_char *cp, u_int length)
{
	register u_int ptr;
	register u_int len;
	int hoplen;
	const char *type;

	if (length < 4) {
		ND_PRINT((ndo, "[bad length %u]", length));
		return;
	}
	ND_PRINT((ndo, " TS{"));
	hoplen = ((cp[3]&0xF) != IPOPT_TS_TSONLY) ? 8 : 4;
	if ((length - 4) & (hoplen-1))
		ND_PRINT((ndo, "[bad length %u]", length));
	ptr = cp[2] - 1;
	len = 0;
	if (ptr < 4 || ((ptr - 4) & (hoplen-1)) || ptr > length + 1)
		ND_PRINT((ndo, "[bad ptr %u]", cp[2]));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -168,7 +168,7 @@
 	return (in_cksum(vec, 2));
 }
 
-static void
+static int
 ip_printts(netdissect_options *ndo,
            register const u_char *cp, u_int length)
 {
@@ -179,16 +179,18 @@
 
 	if (length < 4) {
 		ND_PRINT((ndo, "[bad length %u]", length));
-		return;
+		return (0);
 	}
 	ND_PRINT((ndo, " TS{"));
 	hoplen = ((cp[3]&0xF) != IPOPT_TS_TSONLY) ? 8 : 4;
 	if ((length - 4) & (hoplen-1))
 		ND_PRINT((ndo, "[bad length %u]", length));
+	ND_TCHECK(cp[2]);
 	ptr = cp[2] - 1;
 	len = 0;
 	if (ptr < 4 || ((ptr - 4) & (hoplen-1)) || ptr > length + 1)
 		ND_PRINT((ndo, "[bad ptr %u]", cp[2]));
+	ND_TCHECK(cp[3]);
 	switch (cp[3]&0xF) {
 	case IPOPT_TS_TSONLY:
 		ND_PRINT((ndo, "TSONLY"));
@@ -217,6 +219,7 @@
 	for (len = 4; len < length; len += hoplen) {
 		if (ptr == len)
 			type = " ^ ";
+		ND_TCHECK2(cp[len], hoplen);
 		ND_PRINT((ndo, "%s%d@%s", type, EXTRACT_32BITS(&cp[len+hoplen-4]),
 		       hoplen!=8 ? "" : ipaddr_string(ndo, &cp[len])));
 		type = " ";
@@ -229,6 +232,10 @@
 		ND_PRINT((ndo, " [%d hops not recorded]} ", cp[3]>>4));
 	else
 		ND_PRINT((ndo, "}"));
+	return (0);
+
+trunc:
+	return (-1);
 }
 
 /*
@@ -278,7 +285,8 @@
 			return;
 
 		case IPOPT_TS:
-			ip_printts(ndo, cp, option_len);
+			if (ip_printts(ndo, cp, option_len) == -1)
+				goto trunc;
 			break;
 
 		case IPOPT_RR:       /* fall through */
```
