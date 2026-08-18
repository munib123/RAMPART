# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2719_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2719_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 948-988 of the vulnerable file.

            addr_length =  route_length - sg_length;

            ND_TCHECK2(pptr[0], addr_length);
            offset = strlen(buf);
            snprintf(buf + offset, buflen - offset, ", Originator %s",
                     bgp_vpn_ip_print(ndo, pptr, addr_length << 3));
            break;

        case BGP_MULTICAST_VPN_ROUTE_TYPE_SOURCE_ACTIVE:
            ND_TCHECK2(pptr[0], BGP_VPN_RD_LEN);
            offset = strlen(buf);
            snprintf(buf + offset, buflen - offset, ", RD: %s",
                     bgp_vpn_rd_print(ndo, pptr));
            pptr += BGP_VPN_RD_LEN;

            bgp_vpn_sg_print(ndo, pptr, buf, buflen);
            break;

        case BGP_MULTICAST_VPN_ROUTE_TYPE_SHARED_TREE_JOIN: /* fall through */
        case BGP_MULTICAST_VPN_ROUTE_TYPE_SOURCE_TREE_JOIN:
            ND_TCHECK2(pptr[0], BGP_VPN_RD_LEN);
            offset = strlen(buf);
	    snprintf(buf + offset, buflen - offset, ", RD: %s, Source-AS %s",
		bgp_vpn_rd_print(ndo, pptr),
		as_printf(ndo, astostr, sizeof(astostr),
		EXTRACT_32BITS(pptr + BGP_VPN_RD_LEN)));
            pptr += BGP_VPN_RD_LEN;

            bgp_vpn_sg_print(ndo, pptr, buf, buflen);
            break;

            /*
             * no per route-type printing yet.
             */
        case BGP_MULTICAST_VPN_ROUTE_TYPE_INTRA_AS_SEG_LEAF:
        default:
            break;
        }

        return route_length + 2;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -965,13 +965,13 @@
 
         case BGP_MULTICAST_VPN_ROUTE_TYPE_SHARED_TREE_JOIN: /* fall through */
         case BGP_MULTICAST_VPN_ROUTE_TYPE_SOURCE_TREE_JOIN:
-            ND_TCHECK2(pptr[0], BGP_VPN_RD_LEN);
+            ND_TCHECK2(pptr[0], BGP_VPN_RD_LEN + 4);
             offset = strlen(buf);
 	    snprintf(buf + offset, buflen - offset, ", RD: %s, Source-AS %s",
 		bgp_vpn_rd_print(ndo, pptr),
 		as_printf(ndo, astostr, sizeof(astostr),
 		EXTRACT_32BITS(pptr + BGP_VPN_RD_LEN)));
-            pptr += BGP_VPN_RD_LEN;
+            pptr += BGP_VPN_RD_LEN + 4;
 
             bgp_vpn_sg_print(ndo, pptr, buf, buflen);
             break;
```
