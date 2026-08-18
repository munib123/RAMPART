# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2675_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2675_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 124-164 of the vulnerable file.

		if (ndo->ndo_vflag)
			ND_PRINT((ndo,"%04x:%04x ", panid, EXTRACT_LE_16BITS(p + 2)));
		p += 2;
		caplen -= 2;
		hdrlen += 2;
		break;
	case FC_ADDRESSING_MODE_LONG:
		if (caplen < 2) {
			ND_PRINT((ndo, "[|802.15.4]"));
			return hdrlen;
		}
		panid = EXTRACT_LE_16BITS(p);
		p += 2;
		caplen -= 2;
		hdrlen += 2;
		if (caplen < 8) {
			ND_PRINT((ndo, "[|802.15.4]"));
			return hdrlen;
		}
		if (ndo->ndo_vflag)
			ND_PRINT((ndo,"%04x:%s ", panid, le64addr_string(ndo, p + 2)));
		p += 8;
		caplen -= 8;
		hdrlen += 8;
		break;
	}
	if (ndo->ndo_vflag)
		ND_PRINT((ndo,"< "));

	/*
	 * Source address and PAN ID, if present.
	 */
	switch (FC_SRC_ADDRESSING_MODE(fc)) {
	case FC_ADDRESSING_MODE_NONE:
		if (ndo->ndo_vflag)
			ND_PRINT((ndo,"none "));
		break;
	case FC_ADDRESSING_MODE_RESERVED:
		if (ndo->ndo_vflag)
			ND_PRINT((ndo,"reserved source addressing mode"));
		return 0;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -141,7 +141,7 @@
 			return hdrlen;
 		}
 		if (ndo->ndo_vflag)
-			ND_PRINT((ndo,"%04x:%s ", panid, le64addr_string(ndo, p + 2)));
+			ND_PRINT((ndo,"%04x:%s ", panid, le64addr_string(ndo, p)));
 		p += 8;
 		caplen -= 8;
 		hdrlen += 8;
```
