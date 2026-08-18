# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2697_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2697_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 37-77 of the vulnerable file.

#include "ipproto.h"

static const char tstr[] = "[|ip]";

static const struct tok ip_option_values[] = {
    { IPOPT_EOL, "EOL" },
    { IPOPT_NOP, "NOP" },
    { IPOPT_TS, "timestamp" },
    { IPOPT_SECURITY, "security" },
    { IPOPT_RR, "RR" },
    { IPOPT_SSRR, "SSRR" },
    { IPOPT_LSRR, "LSRR" },
    { IPOPT_RA, "RA" },
    { IPOPT_RFC1393, "traceroute" },
    { 0, NULL }
};

/*
 * print the recorded route in an IP RR, LSRR or SSRR option.
 */
static void
ip_printroute(netdissect_options *ndo,
              register const u_char *cp, u_int length)
{
	register u_int ptr;
	register u_int len;

	if (length < 3) {
		ND_PRINT((ndo, " [bad length %u]", length));
		return;
	}
	if ((length + 1) & 3)
		ND_PRINT((ndo, " [bad length %u]", length));
	ptr = cp[2] - 1;
	if (ptr < 3 || ((ptr + 1) & 3) || ptr > length + 1)
		ND_PRINT((ndo, " [bad ptr %u]", cp[2]));

	for (len = 3; len < length; len += 4) {
		ND_PRINT((ndo, " %s", ipaddr_string(ndo, &cp[len])));
		if (ptr > len)
			ND_PRINT((ndo, ","));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -54,7 +54,7 @@
 /*
  * print the recorded route in an IP RR, LSRR or SSRR option.
  */
-static void
+static int
 ip_printroute(netdissect_options *ndo,
               register const u_char *cp, u_int length)
 {
@@ -63,19 +63,25 @@
 
 	if (length < 3) {
 		ND_PRINT((ndo, " [bad length %u]", length));
-		return;
+		return (0);
 	}
 	if ((length + 1) & 3)
 		ND_PRINT((ndo, " [bad length %u]", length));
+	ND_TCHECK(cp[2]);
 	ptr = cp[2] - 1;
 	if (ptr < 3 || ((ptr + 1) & 3) || ptr > length + 1)
 		ND_PRINT((ndo, " [bad ptr %u]", cp[2]));
 
 	for (len = 3; len < length; len += 4) {
+		ND_TCHECK2(cp[len], 4);
 		ND_PRINT((ndo, " %s", ipaddr_string(ndo, &cp[len])));
 		if (ptr > len)
 			ND_PRINT((ndo, ","));
 	}
+	return (0);
+
+trunc:
+	return (-1);
 }
 
 /*
@@ -278,7 +284,8 @@
 		case IPOPT_RR:       /* fall through */
 		case IPOPT_SSRR:
 		case IPOPT_LSRR:
-			ip_printroute(ndo, cp, option_len);
+			if (ip_printroute(ndo, cp, option_len) == -1)
+				goto trunc;
 			break;
 
 		case IPOPT_RA:
```
