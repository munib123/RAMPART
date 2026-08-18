# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 261_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `261_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 125-165 of the vulnerable file.


	if (version == 2) {
		auth_type = bp[4];
		ND_PRINT((ndo, ", authtype %s", tok2str(auth2str, NULL, auth_type)));
		ND_PRINT((ndo, ", intvl %us, length %u", bp[5], len));
	} else { /* version == 3 */
		uint16_t intvl = (bp[4] & 0x0f) << 8 | bp[5];
		ND_PRINT((ndo, ", intvl %ucs, length %u", intvl, len));
	}

	if (ndo->ndo_vflag) {
		int naddrs = bp[3];
		int i;
		char c;

		if (version == 2 && ND_TTEST2(bp[0], len)) {
			struct cksum_vec vec[1];

			vec[0].ptr = bp;
			vec[0].len = len;
			if (in_cksum(vec, 1))
				ND_PRINT((ndo, ", (bad vrrp cksum %x)",
					EXTRACT_16BITS(&bp[6])));
		}

		if (version == 3 && ND_TTEST2(bp[0], len)) {
			uint16_t cksum = nextproto4_cksum(ndo, (const struct ip *)bp2, bp,
				len, len, IPPROTO_VRRP);
			if (cksum)
				ND_PRINT((ndo, ", (bad vrrp cksum %x)",
					EXTRACT_16BITS(&bp[6])));
		}

		ND_PRINT((ndo, ", addrs"));
		if (naddrs > 1)
			ND_PRINT((ndo, "(%d)", naddrs));
		ND_PRINT((ndo, ":"));
		c = ' ';
		bp += 8;
		for (i = 0; i < naddrs; i++) {
			ND_TCHECK(bp[3]);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -142,9 +142,11 @@
 
 			vec[0].ptr = bp;
 			vec[0].len = len;
-			if (in_cksum(vec, 1))
+			if (in_cksum(vec, 1)) {
+				ND_TCHECK_16BITS(&bp[6]);
 				ND_PRINT((ndo, ", (bad vrrp cksum %x)",
 					EXTRACT_16BITS(&bp[6])));
+			}
 		}
 
 		if (version == 3 && ND_TTEST2(bp[0], len)) {
```
