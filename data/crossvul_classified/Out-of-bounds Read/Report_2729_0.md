# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2729_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2729_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 744-784 of the vulnerable file.

	snprintf(pos, sizeof(rd) - (pos - rd), "%s:%u (%u.%u.%u.%u:%u)",
	    as_printf(ndo, astostr, sizeof(astostr), EXTRACT_32BITS(pptr+2)),
	    EXTRACT_16BITS(pptr+6), *(pptr+2), *(pptr+3), *(pptr+4),
	    *(pptr+5), EXTRACT_16BITS(pptr+6));
        break;
    default:
        snprintf(pos, sizeof(rd) - (pos - rd), "unknown RD format");
        break;
    }
    pos += strlen(pos);
    *(pos) = '\0';
    return (rd);
}

static int
decode_rt_routing_info(netdissect_options *ndo,
                       const u_char *pptr, char *buf, u_int buflen)
{
	uint8_t route_target[8];
	u_int plen;

	ND_TCHECK(pptr[0]);
	plen = pptr[0];   /* get prefix length */

	if (0 == plen) {
		snprintf(buf, buflen, "default route target");
		return 1;
	}

	if (32 > plen)
		return -1;

        plen-=32; /* adjust prefix length */

	if (64 < plen)
		return -1;

	memset(&route_target, 0, sizeof(route_target));
	ND_TCHECK2(pptr[1], (plen + 7) / 8);
	memcpy(&route_target, &pptr[1], (plen + 7) / 8);
	if (plen % 8) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -761,11 +761,18 @@
 {
 	uint8_t route_target[8];
 	u_int plen;
-
+	char asbuf[sizeof(astostr)]; /* bgp_vpn_rd_print() overwrites astostr */
+
+	/* NLRI "prefix length" from RFC 2858 Section 4. */
 	ND_TCHECK(pptr[0]);
 	plen = pptr[0];   /* get prefix length */
 
+	/* NLRI "prefix" (ibid), valid lengths are { 0, 32, 33, ..., 96 } bits.
+	 * RFC 4684 Section 4 defines the layout of "origin AS" and "route
+	 * target" fields inside the "prefix" depending on its length.
+	 */
 	if (0 == plen) {
+		/* Without "origin AS", without "route target". */
 		snprintf(buf, buflen, "default route target");
 		return 1;
 	}
@@ -773,20 +780,29 @@
 	if (32 > plen)
 		return -1;
 
+	/* With at least "origin AS", possibly with "route target". */
+	ND_TCHECK_32BITS(pptr + 1);
+	as_printf(ndo, asbuf, sizeof(asbuf), EXTRACT_32BITS(pptr + 1));
+
         plen-=32; /* adjust prefix length */
 
 	if (64 < plen)
 		return -1;
 
+	/* From now on (plen + 7) / 8 evaluates to { 0, 1, 2, ..., 8 }
+	 * and gives the number of octets in the variable-length "route
+	 * target" field inside this NLRI "prefix". Look for it.
+	 */
 	memset(&route_target, 0, sizeof(route_target));
-	ND_TCHECK2(pptr[1], (plen + 7) / 8);
-	memcpy(&route_target, &pptr[1], (plen + 7) / 8);
+	ND_TCHECK2(pptr[5], (plen + 7) / 8);
+	memcpy(&route_target, &pptr[5], (plen + 7) / 8);
+	/* Which specification says to do this? */
 	if (plen % 8) {
 		((u_char *)&route_target)[(plen + 7) / 8 - 1] &=
 			((0xff00 >> (plen % 8)) & 0xff);
 	}
 	snprintf(buf, buflen, "origin AS: %s, route target %s",
-	    as_printf(ndo, astostr, sizeof(astostr), EXTRACT_32BITS(pptr+1)),
+	    asbuf,
 	    bgp_vpn_rd_print(ndo, (u_char *)&route_target));
 
 	return 5 + (plen + 7) / 8;
```
