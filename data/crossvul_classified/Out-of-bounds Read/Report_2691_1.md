# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2691_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2691_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1200-1241 of the vulnerable file.

		}
		snpa = pptr;
		pptr += snpal;
                li -= snpal;
		ND_TCHECK(*pptr);
		if (li < 1) {
			ND_PRINT((ndo, ", bad redirect/li"));
			return;
		}
		netal = *pptr;
		pptr++;
		ND_TCHECK2(*pptr, netal);
		if (li < netal) {
			ND_PRINT((ndo, ", bad redirect/li"));
			return;
		}
		neta = pptr;
		pptr += netal;
                li -= netal;

		if (netal == 0)
			ND_PRINT((ndo, "\n\t  %s", etheraddr_string(ndo, snpa)));
		else
			ND_PRINT((ndo, "\n\t  %s", isonsap_string(ndo, neta, netal)));
		break;
	}

	case ESIS_PDU_ESH:
            ND_TCHECK(*pptr);
            if (li < 1) {
                ND_PRINT((ndo, ", bad esh/li"));
                return;
            }
            source_address_number = *pptr;
            pptr++;
            li--;

            ND_PRINT((ndo, "\n\t  Number of Source Addresses: %u", source_address_number));

            while (source_address_number > 0) {
                ND_TCHECK(*pptr);
            	if (li < 1) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1217,10 +1217,18 @@
 		pptr += netal;
                 li -= netal;
 
-		if (netal == 0)
-			ND_PRINT((ndo, "\n\t  %s", etheraddr_string(ndo, snpa)));
+		if (snpal == 6)
+			ND_PRINT((ndo, "\n\t  SNPA (length: %u): %s",
+			       snpal,
+			       etheraddr_string(ndo, snpa)));
 		else
-			ND_PRINT((ndo, "\n\t  %s", isonsap_string(ndo, neta, netal)));
+			ND_PRINT((ndo, "\n\t  SNPA (length: %u): %s",
+			       snpal,
+			       linkaddr_string(ndo, snpa, LINKADDR_OTHER, snpal)));
+		if (netal != 0)
+			ND_PRINT((ndo, "\n\t  NET (length: %u) %s",
+			       netal,
+			       isonsap_string(ndo, neta, netal)));
 		break;
 	}
 
```
