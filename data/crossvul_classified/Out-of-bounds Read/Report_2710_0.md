# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2710_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2710_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 152-192 of the vulnerable file.

	register char ch;
	uint16_t sport, dport;
	u_int nla_afnum;
	char nla_buf[INET6_ADDRSTRLEN];
	register const struct ip6_hdr *ip6;
	uint8_t opt_type, opt_len;
	uint32_t seq, opts_len, len, offset;

	pgm = (const struct pgm_header *)bp;
	ip = (const struct ip *)bp2;
	if (IP_V(ip) == 6)
		ip6 = (const struct ip6_hdr *)bp2;
	else
		ip6 = NULL;
	ch = '\0';
	if (!ND_TTEST(pgm->pgm_dport)) {
		if (ip6) {
			ND_PRINT((ndo, "%s > %s: [|pgm]",
				ip6addr_string(ndo, &ip6->ip6_src),
				ip6addr_string(ndo, &ip6->ip6_dst)));
			return;
		} else {
			ND_PRINT((ndo, "%s > %s: [|pgm]",
				ipaddr_string(ndo, &ip->ip_src),
				ipaddr_string(ndo, &ip->ip_dst)));
			return;
		}
	}

	sport = EXTRACT_16BITS(&pgm->pgm_sport);
	dport = EXTRACT_16BITS(&pgm->pgm_dport);

	if (ip6) {
		if (ip6->ip6_nxt == IPPROTO_PGM) {
			ND_PRINT((ndo, "%s.%s > %s.%s: ",
				ip6addr_string(ndo, &ip6->ip6_src),
				tcpport_string(ndo, sport),
				ip6addr_string(ndo, &ip6->ip6_dst),
				tcpport_string(ndo, dport)));
		} else {
			ND_PRINT((ndo, "%s > %s: ",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -169,13 +169,12 @@
 			ND_PRINT((ndo, "%s > %s: [|pgm]",
 				ip6addr_string(ndo, &ip6->ip6_src),
 				ip6addr_string(ndo, &ip6->ip6_dst)));
-			return;
 		} else {
 			ND_PRINT((ndo, "%s > %s: [|pgm]",
 				ipaddr_string(ndo, &ip->ip_src),
 				ipaddr_string(ndo, &ip->ip_dst)));
-			return;
 		}
+		return;
 	}
 
 	sport = EXTRACT_16BITS(&pgm->pgm_sport);
@@ -362,6 +361,7 @@
 	     * and stopping if we don't have enough.
 	     */
 	    bp += (2 * sizeof(uint16_t));
+	    ND_TCHECK_16BITS(bp);
 	    switch (EXTRACT_16BITS(bp)) {
 	    case AFNUM_INET:
 		ND_TCHECK2(*bp, sizeof(struct in_addr));
```
