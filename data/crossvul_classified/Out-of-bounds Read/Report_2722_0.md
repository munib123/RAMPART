# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2722_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2722_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 2106-2146 of the vulnerable file.

                                       *(tptr+3),
                               EXTRACT_16BITS(tptr+4)));
                        break;
                    case BGP_EXT_COM_SOURCE_AS:
                        ND_PRINT((ndo, ": AS %u", EXTRACT_16BITS(tptr+2)));
                        break;
                    default:
                        ND_TCHECK2(*tptr,8);
                        print_unknown_data(ndo, tptr, "\n\t      ", 8);
                        break;
                    }
                    tlen -=8;
                    tptr +=8;
                }
                break;

        case BGPTYPE_PMSI_TUNNEL:
        {
                uint8_t tunnel_type, flags;

                tunnel_type = *(tptr+1);
                flags = *tptr;
                tlen = len;

                ND_TCHECK2(tptr[0], 5);
                ND_PRINT((ndo, "\n\t    Tunnel-type %s (%u), Flags [%s], MPLS Label %u",
                       tok2str(bgp_pmsi_tunnel_values, "Unknown", tunnel_type),
                       tunnel_type,
                       bittok2str(bgp_pmsi_flag_values, "none", flags),
                       EXTRACT_24BITS(tptr+2)>>4));

                tptr +=5;
                tlen -= 5;

                switch (tunnel_type) {
                case BGP_PMSI_TUNNEL_PIM_SM: /* fall through */
                case BGP_PMSI_TUNNEL_PIM_BIDIR:
                    ND_TCHECK2(tptr[0], 8);
                    ND_PRINT((ndo, "\n\t      Sender %s, P-Group %s",
                           ipaddr_string(ndo, tptr),
                           ipaddr_string(ndo, tptr+4)));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2123,11 +2123,11 @@
         {
                 uint8_t tunnel_type, flags;
 
+                ND_TCHECK2(tptr[0], 5);
                 tunnel_type = *(tptr+1);
                 flags = *tptr;
                 tlen = len;
 
-                ND_TCHECK2(tptr[0], 5);
                 ND_PRINT((ndo, "\n\t    Tunnel-type %s (%u), Flags [%s], MPLS Label %u",
                        tok2str(bgp_pmsi_tunnel_values, "Unknown", tunnel_type),
                        tunnel_type,
```
