# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2754_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2754_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 28-68 of the vulnerable file.

#include <netdissect-stdinc.h>

#include <string.h>

#include "ip6.h"

#include "netdissect.h"
#include "addrtoname.h"
#include "extract.h"

int
rt6_print(netdissect_options *ndo, register const u_char *bp, const u_char *bp2 _U_)
{
	register const struct ip6_rthdr *dp;
	register const struct ip6_rthdr0 *dp0;
	register const u_char *ep;
	int i, len;
	register const struct in6_addr *addr;

	dp = (const struct ip6_rthdr *)bp;
	len = dp->ip6r_len;

	/* 'ep' points to the end of available data. */
	ep = ndo->ndo_snapend;

	ND_TCHECK(dp->ip6r_segleft);

	ND_PRINT((ndo, "srcrt (len=%d", dp->ip6r_len));	/*)*/
	ND_PRINT((ndo, ", type=%d", dp->ip6r_type));
	ND_PRINT((ndo, ", segleft=%d", dp->ip6r_segleft));

	switch (dp->ip6r_type) {
	case IPV6_RTHDR_TYPE_0:
	case IPV6_RTHDR_TYPE_2:			/* Mobile IPv6 ID-20 */
		dp0 = (const struct ip6_rthdr0 *)dp;

		ND_TCHECK(dp0->ip6r0_reserved);
		if (dp0->ip6r0_reserved || ndo->ndo_vflag) {
			ND_PRINT((ndo, ", rsv=0x%0x",
			    EXTRACT_32BITS(&dp0->ip6r0_reserved)));
		}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -45,13 +45,13 @@
 	register const struct in6_addr *addr;
 
 	dp = (const struct ip6_rthdr *)bp;
-	len = dp->ip6r_len;
 
 	/* 'ep' points to the end of available data. */
 	ep = ndo->ndo_snapend;
 
 	ND_TCHECK(dp->ip6r_segleft);
 
+	len = dp->ip6r_len;
 	ND_PRINT((ndo, "srcrt (len=%d", dp->ip6r_len));	/*)*/
 	ND_PRINT((ndo, ", type=%d", dp->ip6r_type));
 	ND_PRINT((ndo, ", segleft=%d", dp->ip6r_segleft));
```
