# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2664_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2664_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1389-1429 of the vulnerable file.

		}
                if (!len) {
			ND_PRINT((ndo, "empty"));
			break;
                }

                /*
                 * BGP updates exchanged between New speakers that support 4
                 * byte AS, ASs are always encoded in 4 bytes. There is no
                 * definitive way to find this, just by the packet's
                 * contents. So, check for packet's TLV's sanity assuming
                 * 2 bytes first, and it does not pass, assume that ASs are
                 * encoded in 4 bytes format and move on.
                 */
                as_size = bgp_attr_get_as_size(ndo, atype, pptr, len);

		while (tptr < pptr + len) {
			ND_TCHECK(tptr[0]);
                        ND_PRINT((ndo, "%s", tok2str(bgp_as_path_segment_open_values,
						"?", tptr[0])));
                        for (i = 0; i < tptr[1] * as_size; i += as_size) {
                            ND_TCHECK2(tptr[2 + i], as_size);
			    ND_PRINT((ndo, "%s ",
				as_printf(ndo, astostr, sizeof(astostr),
				as_size == 2 ?
				EXTRACT_16BITS(&tptr[2 + i]) :
				EXTRACT_32BITS(&tptr[2 + i]))));
                        }
			ND_TCHECK(tptr[0]);
                        ND_PRINT((ndo, "%s", tok2str(bgp_as_path_segment_close_values,
						"?", tptr[0])));
                        ND_TCHECK(tptr[1]);
                        tptr += 2 + tptr[1] * as_size;
		}
		break;
	case BGPTYPE_NEXT_HOP:
		if (len != 4)
			ND_PRINT((ndo, "invalid len"));
		else {
			ND_TCHECK2(tptr[0], 4);
			ND_PRINT((ndo, "%s", ipaddr_string(ndo, tptr)));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1406,6 +1406,7 @@
 			ND_TCHECK(tptr[0]);
                         ND_PRINT((ndo, "%s", tok2str(bgp_as_path_segment_open_values,
 						"?", tptr[0])));
+			ND_TCHECK(tptr[1]);
                         for (i = 0; i < tptr[1] * as_size; i += as_size) {
                             ND_TCHECK2(tptr[2 + i], as_size);
 			    ND_PRINT((ndo, "%s ",
```
