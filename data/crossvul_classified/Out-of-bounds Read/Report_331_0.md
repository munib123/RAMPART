# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 331_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `331_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1683-1723 of the vulnerable file.

                        case (AFNUM_NSAP<<8 | SAFNUM_MULTICAST):
                        case (AFNUM_NSAP<<8 | SAFNUM_UNIMULTICAST):
                            ND_TCHECK2(tptr[0], tlen);
                            ND_PRINT((ndo, "%s", isonsap_string(ndo, tptr, tlen)));
                            tptr += tlen;
                            tlen = 0;
                            break;

                        case (AFNUM_NSAP<<8 | SAFNUM_VPNUNICAST):
                        case (AFNUM_NSAP<<8 | SAFNUM_VPNMULTICAST):
                        case (AFNUM_NSAP<<8 | SAFNUM_VPNUNIMULTICAST):
                            if (tlen < BGP_VPN_RD_LEN+1) {
                                ND_PRINT((ndo, "invalid len"));
                                tlen = 0;
                            } else {
                                ND_TCHECK2(tptr[0], tlen);
                                ND_PRINT((ndo, "RD: %s, %s",
                                       bgp_vpn_rd_print(ndo, tptr),
                                       isonsap_string(ndo, tptr+BGP_VPN_RD_LEN,tlen-BGP_VPN_RD_LEN)));
                                /* rfc986 mapped IPv4 address ? */
                                if (EXTRACT_32BITS(tptr+BGP_VPN_RD_LEN) ==  0x47000601)
                                    ND_PRINT((ndo, " = %s", ipaddr_string(ndo, tptr+BGP_VPN_RD_LEN+4)));
                                /* rfc1888 mapped IPv6 address ? */
                                else if (EXTRACT_24BITS(tptr+BGP_VPN_RD_LEN) ==  0x350000)
                                    ND_PRINT((ndo, " = %s", ip6addr_string(ndo, tptr+BGP_VPN_RD_LEN+3)));
                                tptr += tlen;
                                tlen = 0;
                            }
                            break;
                        default:
                            ND_TCHECK2(tptr[0], tlen);
                            ND_PRINT((ndo, "no AFI %u/SAFI %u decoder", af, safi));
                            if (ndo->ndo_vflag <= 1)
                                print_unknown_data(ndo, tptr, "\n\t    ", tlen);
                            tptr += tlen;
                            tlen = 0;
                            goto done;
                            break;
                        }
                    }
		}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1700,10 +1700,12 @@
                                        bgp_vpn_rd_print(ndo, tptr),
                                        isonsap_string(ndo, tptr+BGP_VPN_RD_LEN,tlen-BGP_VPN_RD_LEN)));
                                 /* rfc986 mapped IPv4 address ? */
-                                if (EXTRACT_32BITS(tptr+BGP_VPN_RD_LEN) ==  0x47000601)
+                                if (tlen == BGP_VPN_RD_LEN + 4 + sizeof(struct in_addr)
+                                    && EXTRACT_32BITS(tptr+BGP_VPN_RD_LEN) ==  0x47000601)
                                     ND_PRINT((ndo, " = %s", ipaddr_string(ndo, tptr+BGP_VPN_RD_LEN+4)));
                                 /* rfc1888 mapped IPv6 address ? */
-                                else if (EXTRACT_24BITS(tptr+BGP_VPN_RD_LEN) ==  0x350000)
+                                else if (tlen == BGP_VPN_RD_LEN + 3 + sizeof(struct in6_addr)
+                                         && EXTRACT_24BITS(tptr+BGP_VPN_RD_LEN) ==  0x350000)
                                     ND_PRINT((ndo, " = %s", ip6addr_string(ndo, tptr+BGP_VPN_RD_LEN+3)));
                                 tptr += tlen;
                                 tlen = 0;
```
