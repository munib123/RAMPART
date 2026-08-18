# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2731_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2731_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1844-1884 of the vulnerable file.

	case ISIS_SUBTLV_EXT_IS_REACH_RESERVABLE_BW:
            if (subl >= 4) {
              bw.i = EXTRACT_32BITS(tptr);
              ND_PRINT((ndo, ", %.3f Mbps", bw.f * 8 / 1000000));
            }
            break;
        case ISIS_SUBTLV_EXT_IS_REACH_UNRESERVED_BW :
            if (subl >= 32) {
              for (te_class = 0; te_class < 8; te_class++) {
                bw.i = EXTRACT_32BITS(tptr);
                ND_PRINT((ndo, "%s  TE-Class %u: %.3f Mbps",
                       ident,
                       te_class,
                       bw.f * 8 / 1000000));
		tptr+=4;
	      }
            }
            break;
        case ISIS_SUBTLV_EXT_IS_REACH_BW_CONSTRAINTS: /* fall through */
        case ISIS_SUBTLV_EXT_IS_REACH_BW_CONSTRAINTS_OLD:
            ND_PRINT((ndo, "%sBandwidth Constraints Model ID: %s (%u)",
                   ident,
                   tok2str(diffserv_te_bc_values, "unknown", *tptr),
                   *tptr));
            tptr++;
            /* decode BCs until the subTLV ends */
            for (te_class = 0; te_class < (subl-1)/4; te_class++) {
                ND_TCHECK2(*tptr, 4);
                bw.i = EXTRACT_32BITS(tptr);
                ND_PRINT((ndo, "%s  Bandwidth constraint CT%u: %.3f Mbps",
                       ident,
                       te_class,
                       bw.f * 8 / 1000000));
		tptr+=4;
            }
            break;
        case ISIS_SUBTLV_EXT_IS_REACH_TE_METRIC:
            if (subl >= 3)
              ND_PRINT((ndo, ", %u", EXTRACT_24BITS(tptr)));
            break;
        case ISIS_SUBTLV_EXT_IS_REACH_LINK_ATTRIBUTE:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1861,6 +1861,8 @@
             break;
         case ISIS_SUBTLV_EXT_IS_REACH_BW_CONSTRAINTS: /* fall through */
         case ISIS_SUBTLV_EXT_IS_REACH_BW_CONSTRAINTS_OLD:
+            if (subl == 0)
+                break;
             ND_PRINT((ndo, "%sBandwidth Constraints Model ID: %s (%u)",
                    ident,
                    tok2str(diffserv_te_bc_values, "unknown", *tptr),
@@ -1868,7 +1870,6 @@
             tptr++;
             /* decode BCs until the subTLV ends */
             for (te_class = 0; te_class < (subl-1)/4; te_class++) {
-                ND_TCHECK2(*tptr, 4);
                 bw.i = EXTRACT_32BITS(tptr);
                 ND_PRINT((ndo, "%s  Bandwidth constraint CT%u: %.3f Mbps",
                        ident,
```
