# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2657_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2657_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 263-303 of the vulnerable file.

#endif

            ND_PRINT((ndo, "hlim %u, next-header %s (%u) payload length: %u) ",
                         ip6->ip6_hlim,
                         tok2str(ipproto_values,"unknown",ip6->ip6_nxt),
                         ip6->ip6_nxt,
                         payload_len));
        }

	/*
	 * Cut off the snapshot length to the end of the IP payload.
	 */
	ipend = bp + len;
	if (ipend < ndo->ndo_snapend)
		ndo->ndo_snapend = ipend;

	cp = (const u_char *)ip6;
	advance = sizeof(struct ip6_hdr);
	nh = ip6->ip6_nxt;
	while (cp < ndo->ndo_snapend && advance > 0) {
		cp += advance;
		len -= advance;

		if (cp == (const u_char *)(ip6 + 1) &&
		    nh != IPPROTO_TCP && nh != IPPROTO_UDP &&
		    nh != IPPROTO_DCCP && nh != IPPROTO_SCTP) {
			ND_PRINT((ndo, "%s > %s: ", ip6addr_string(ndo, &ip6->ip6_src),
				     ip6addr_string(ndo, &ip6->ip6_dst)));
		}

		switch (nh) {
		case IPPROTO_HOPOPTS:
			advance = hbhopt_print(ndo, cp);
			if (advance < 0)
				return;
			nh = *cp;
			break;
		case IPPROTO_DSTOPTS:
			advance = dstopt_print(ndo, cp);
			if (advance < 0)
				return;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -280,6 +280,8 @@
 	advance = sizeof(struct ip6_hdr);
 	nh = ip6->ip6_nxt;
 	while (cp < ndo->ndo_snapend && advance > 0) {
+		if (len < (u_int)advance)
+			goto trunc;
 		cp += advance;
 		len -= advance;
 
@@ -322,10 +324,15 @@
 			 * mobility header.
 			 */
 			advance = mobility_print(ndo, cp, (const u_char *)ip6);
+			if (advance < 0)
+				return;
 			nh = *cp;
 			return;
 		case IPPROTO_ROUTING:
+			ND_TCHECK(*cp);
 			advance = rt6_print(ndo, cp, (const u_char *)ip6);
+			if (advance < 0)
+				return;
 			nh = *cp;
 			break;
 		case IPPROTO_SCTP:
@@ -345,12 +352,16 @@
 			return;
 		case IPPROTO_AH:
 			advance = ah_print(ndo, cp);
+			if (advance < 0)
+				return;
 			nh = *cp;
 			break;
 		case IPPROTO_ESP:
 		    {
 			int enh, padlen;
 			advance = esp_print(ndo, cp, len, (const u_char *)ip6, &enh, &padlen);
+			if (advance < 0)
+				return;
 			nh = enh & 0xff;
 			len -= padlen;
 			break;
```
