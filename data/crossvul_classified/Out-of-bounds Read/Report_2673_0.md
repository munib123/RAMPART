# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2673_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2673_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 105-145 of the vulnerable file.

			ND_PRINT((ndo,"none "));
		break;
	case FC_ADDRESSING_MODE_RESERVED:
		if (ndo->ndo_vflag)
			ND_PRINT((ndo,"reserved destination addressing mode"));
		return hdrlen;
	case FC_ADDRESSING_MODE_SHORT:
		if (caplen < 2) {
			ND_PRINT((ndo, "[|802.15.4]"));
			return hdrlen;
		}
		panid = EXTRACT_LE_16BITS(p);
		p += 2;
		caplen -= 2;
		hdrlen += 2;
		if (caplen < 2) {
			ND_PRINT((ndo, "[|802.15.4]"));
			return hdrlen;
		}
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
			ND_PRINT((ndo,"%04x:%s ", panid, le64addr_string(ndo, p)));
		p += 8;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -122,7 +122,7 @@
 			return hdrlen;
 		}
 		if (ndo->ndo_vflag)
-			ND_PRINT((ndo,"%04x:%04x ", panid, EXTRACT_LE_16BITS(p + 2)));
+			ND_PRINT((ndo,"%04x:%04x ", panid, EXTRACT_LE_16BITS(p)));
 		p += 2;
 		caplen -= 2;
 		hdrlen += 2;
```
