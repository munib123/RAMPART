# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 328_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `328_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 2041-2081 of the vulnerable file.

		fcslen = caplen - length;
		caplen -= fcslen;
		ndo->ndo_snapend -= fcslen;
	}

	if (caplen < IEEE802_11_FC_LEN) {
		ND_PRINT((ndo, "%s", tstr));
		return orig_caplen;
	}

	fc = EXTRACT_LE_16BITS(p);
	hdrlen = extract_header_length(ndo, fc);
	if (hdrlen == 0) {
		/* Unknown frame type or control frame subtype; quit. */
		return (0);
	}
	if (pad)
		hdrlen = roundup2(hdrlen, 4);
	if (ndo->ndo_Hflag && FC_TYPE(fc) == T_DATA &&
	    DATA_FRAME_IS_QOS(FC_SUBTYPE(fc))) {
		meshdrlen = extract_mesh_header_length(p+hdrlen);
		hdrlen += meshdrlen;
	} else
		meshdrlen = 0;

	if (caplen < hdrlen) {
		ND_PRINT((ndo, "%s", tstr));
		return hdrlen;
	}

	if (ndo->ndo_eflag)
		ieee_802_11_hdr_print(ndo, fc, p, hdrlen, meshdrlen);

	/*
	 * Go past the 802.11 header.
	 */
	length -= hdrlen;
	caplen -= hdrlen;
	p += hdrlen;

	src.addr_string = etheraddr_string;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2058,6 +2058,10 @@
 		hdrlen = roundup2(hdrlen, 4);
 	if (ndo->ndo_Hflag && FC_TYPE(fc) == T_DATA &&
 	    DATA_FRAME_IS_QOS(FC_SUBTYPE(fc))) {
+		if (caplen < hdrlen + 1) {
+			ND_PRINT((ndo, "%s", tstr));
+			return hdrlen;
+		}
 		meshdrlen = extract_mesh_header_length(p+hdrlen);
 		hdrlen += meshdrlen;
 	} else
```
