# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2644_3
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2644_3`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 350-390 of the vulnerable file.

	case ETHERTYPE_ATALK:
		if (ndo->ndo_vflag)
			ND_PRINT((ndo, "et1 "));
		atalk_print(ndo, p, length);
		return (1);

	case ETHERTYPE_AARP:
		aarp_print(ndo, p, length);
		return (1);

	case ETHERTYPE_IPX:
		ND_PRINT((ndo, "(NOV-ETHII) "));
		ipx_print(ndo, p, length);
		return (1);

	case ETHERTYPE_ISO:
		if (length == 0 || caplen == 0) {
			ND_PRINT((ndo, " [|osi]"));
			return (1);
		}
		isoclns_print(ndo, p + 1, length - 1, caplen - 1);
		return(1);

	case ETHERTYPE_PPPOED:
	case ETHERTYPE_PPPOES:
	case ETHERTYPE_PPPOED2:
	case ETHERTYPE_PPPOES2:
		pppoe_print(ndo, p, length);
		return (1);

	case ETHERTYPE_EAPOL:
	        eap_print(ndo, p, length);
		return (1);

	case ETHERTYPE_RRCP:
	        rrcp_print(ndo, p, length, src, dst);
		return (1);

	case ETHERTYPE_PPP:
		if (length) {
			ND_PRINT((ndo, ": "));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -367,7 +367,7 @@
 			ND_PRINT((ndo, " [|osi]"));
 			return (1);
 		}
-		isoclns_print(ndo, p + 1, length - 1, caplen - 1);
+		isoclns_print(ndo, p + 1, length - 1);
 		return(1);
 
 	case ETHERTYPE_PPPOED:
```
