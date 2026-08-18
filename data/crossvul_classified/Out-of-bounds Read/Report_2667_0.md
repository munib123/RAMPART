# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2667_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2667_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 2165-2206 of the vulnerable file.

                           EXTRACT_32BITS(tptr+4)));
                    break;
                case BGP_PMSI_TUNNEL_RSVP_P2MP:
                    ND_TCHECK2(tptr[0], 8);
                    ND_PRINT((ndo, "\n\t      Extended-Tunnel-ID %s, P2MP-ID 0x%08x",
                           ipaddr_string(ndo, tptr),
                           EXTRACT_32BITS(tptr+4)));
                    break;
                default:
                    if (ndo->ndo_vflag <= 1) {
                        print_unknown_data(ndo, tptr, "\n\t      ", tlen);
                    }
                }
                break;
        }
	case BGPTYPE_AIGP:
	{
		uint8_t type;
		uint16_t length;

		ND_TCHECK2(tptr[0], 3);

		tlen = len;

		while (tlen >= 3) {

		    type = *tptr;
		    length = EXTRACT_16BITS(tptr+1);

		    ND_PRINT((ndo, "\n\t    %s TLV (%u), length %u",
			      tok2str(bgp_aigp_values, "Unknown", type),
			      type, length));

		    /*
		     * Check if we can read the TLV data.
		     */
		    ND_TCHECK2(tptr[3], length - 3);

		    switch (type) {

		    case BGP_AIGP_TLV:
		        ND_TCHECK2(tptr[3], 8);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2182,35 +2182,42 @@
 		uint8_t type;
 		uint16_t length;
 
-		ND_TCHECK2(tptr[0], 3);
-
 		tlen = len;
 
 		while (tlen >= 3) {
+
+		    ND_TCHECK2(tptr[0], 3);
 
 		    type = *tptr;
 		    length = EXTRACT_16BITS(tptr+1);
+		    tptr += 3;
+		    tlen -= 3;
 
 		    ND_PRINT((ndo, "\n\t    %s TLV (%u), length %u",
 			      tok2str(bgp_aigp_values, "Unknown", type),
 			      type, length));
 
+		    if (length < 3)
+			goto trunc;
+		    length -= 3;
+
 		    /*
 		     * Check if we can read the TLV data.
 		     */
-		    ND_TCHECK2(tptr[3], length - 3);
+		    ND_TCHECK2(tptr[3], length);
 
 		    switch (type) {
 
 		    case BGP_AIGP_TLV:
-		        ND_TCHECK2(tptr[3], 8);
+		        if (length < 8)
+		            goto trunc;
 			ND_PRINT((ndo, ", metric %" PRIu64,
-				  EXTRACT_64BITS(tptr+3)));
+				  EXTRACT_64BITS(tptr)));
 			break;
 
 		    default:
 			if (ndo->ndo_vflag <= 1) {
-			    print_unknown_data(ndo, tptr+3,"\n\t      ", length-3);
+			    print_unknown_data(ndo, tptr,"\n\t      ", length);
 			}
 		    }
 
```
