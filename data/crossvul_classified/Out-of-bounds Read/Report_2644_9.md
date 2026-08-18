# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2644_9
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2644_9`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 184-222 of the vulnerable file.

	/*
	 * Print the payload.
	 */
	if (pt == PT_UNKNOWN) {
		if (!ndo->ndo_suppress_default_print)
			ND_DEFAULTPRINT(p, length);
		return;
	}
	ND_PRINT((ndo, ndo->ndo_vflag ? "\n\t" : " "));
	switch (pt) {

	case PT_IPV4:
		ip_print(ndo, p, length);
		break;

	case PT_IPV6:
		ip6_print(ndo, p, length);
		break;

	case PT_OSI:
		isoclns_print(ndo, p, length, length);
		break;

	default:
		break;
	}
	return;

trunc:
	ND_PRINT((ndo, "[|MPLS]"));
}


/*
 * Local Variables:
 * c-style: whitesmith
 * c-basic-offset: 8
 * End:
 */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -201,7 +201,7 @@
 		break;
 
 	case PT_OSI:
-		isoclns_print(ndo, p, length, length);
+		isoclns_print(ndo, p, length);
 		break;
 
 	default:
```
