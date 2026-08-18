# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2648_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2648_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 883-923 of the vulnerable file.


return -2;
}

#define BGP_MULTICAST_VPN_ROUTE_TYPE_INTRA_AS_I_PMSI   1
#define BGP_MULTICAST_VPN_ROUTE_TYPE_INTER_AS_I_PMSI   2
#define BGP_MULTICAST_VPN_ROUTE_TYPE_S_PMSI            3
#define BGP_MULTICAST_VPN_ROUTE_TYPE_INTRA_AS_SEG_LEAF 4
#define BGP_MULTICAST_VPN_ROUTE_TYPE_SOURCE_ACTIVE     5
#define BGP_MULTICAST_VPN_ROUTE_TYPE_SHARED_TREE_JOIN  6
#define BGP_MULTICAST_VPN_ROUTE_TYPE_SOURCE_TREE_JOIN  7

static const struct tok bgp_multicast_vpn_route_type_values[] = {
    { BGP_MULTICAST_VPN_ROUTE_TYPE_INTRA_AS_I_PMSI, "Intra-AS I-PMSI"},
    { BGP_MULTICAST_VPN_ROUTE_TYPE_INTER_AS_I_PMSI, "Inter-AS I-PMSI"},
    { BGP_MULTICAST_VPN_ROUTE_TYPE_S_PMSI, "S-PMSI"},
    { BGP_MULTICAST_VPN_ROUTE_TYPE_INTRA_AS_SEG_LEAF, "Intra-AS Segment-Leaf"},
    { BGP_MULTICAST_VPN_ROUTE_TYPE_SOURCE_ACTIVE, "Source-Active"},
    { BGP_MULTICAST_VPN_ROUTE_TYPE_SHARED_TREE_JOIN, "Shared Tree Join"},
    { BGP_MULTICAST_VPN_ROUTE_TYPE_SOURCE_TREE_JOIN, "Source Tree Join"},
};

static int
decode_multicast_vpn(netdissect_options *ndo,
                     const u_char *pptr, char *buf, u_int buflen)
{
        uint8_t route_type, route_length, addr_length, sg_length;
        u_int offset;

	ND_TCHECK2(pptr[0], 2);
        route_type = *pptr++;
        route_length = *pptr++;

        snprintf(buf, buflen, "Route-Type: %s (%u), length: %u",
                 tok2str(bgp_multicast_vpn_route_type_values,
                         "Unknown", route_type),
                 route_type, route_length);

        switch(route_type) {
        case BGP_MULTICAST_VPN_ROUTE_TYPE_INTRA_AS_I_PMSI:
            ND_TCHECK2(pptr[0], BGP_VPN_RD_LEN);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -900,6 +900,7 @@
     { BGP_MULTICAST_VPN_ROUTE_TYPE_SOURCE_ACTIVE, "Source-Active"},
     { BGP_MULTICAST_VPN_ROUTE_TYPE_SHARED_TREE_JOIN, "Shared Tree Join"},
     { BGP_MULTICAST_VPN_ROUTE_TYPE_SOURCE_TREE_JOIN, "Source Tree Join"},
+    { 0, NULL}
 };
 
 static int
```
