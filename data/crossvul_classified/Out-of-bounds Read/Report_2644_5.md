# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2644_5
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2644_5`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 210-250 of the vulnerable file.

        else
            ND_PRINT((ndo, "\n\t")); /* if verbose go multiline */

	switch (prot) {
	case ETHERTYPE_IP:
	        ip_print(ndo, bp, len);
		break;
	case ETHERTYPE_IPV6:
		ip6_print(ndo, bp, len);
		break;
	case ETHERTYPE_MPLS:
		mpls_print(ndo, bp, len);
		break;
	case ETHERTYPE_IPX:
		ipx_print(ndo, bp, len);
		break;
	case ETHERTYPE_ATALK:
		atalk_print(ndo, bp, len);
		break;
	case ETHERTYPE_GRE_ISO:
		isoclns_print(ndo, bp, len, ndo->ndo_snapend - bp);
		break;
	case ETHERTYPE_TEB:
		ether_print(ndo, bp, len, ndo->ndo_snapend - bp, NULL, NULL);
		break;
	default:
		ND_PRINT((ndo, "gre-proto-0x%x", prot));
	}
	return;

trunc:
	ND_PRINT((ndo, "%s", tstr));
}

static void
gre_print_1(netdissect_options *ndo, const u_char *bp, u_int length)
{
	u_int len = length;
	uint16_t flags, prot;

	/* 16 bits ND_TCHECKed in gre_print() */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -227,7 +227,7 @@
 		atalk_print(ndo, bp, len);
 		break;
 	case ETHERTYPE_GRE_ISO:
-		isoclns_print(ndo, bp, len, ndo->ndo_snapend - bp);
+		isoclns_print(ndo, bp, len);
 		break;
 	case ETHERTYPE_TEB:
 		ether_print(ndo, bp, len, ndo->ndo_snapend - bp, NULL, NULL);
```
