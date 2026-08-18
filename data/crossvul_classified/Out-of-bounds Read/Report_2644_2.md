# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2644_2
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2644_2`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 80-120 of the vulnerable file.

	case CHDLC_TYPE_SLARP:
		chdlc_slarp_print(ndo, p, length);
		break;
#if 0
	case CHDLC_TYPE_CDP:
		chdlc_cdp_print(p, length);
		break;
#endif
        case ETHERTYPE_MPLS:
        case ETHERTYPE_MPLS_MULTI:
                mpls_print(ndo, p, length);
		break;
        case ETHERTYPE_ISO:
                /* is the fudge byte set ? lets verify by spotting ISO headers */
                if (length < 2)
                    goto trunc;
                ND_TCHECK_16BITS(p);
                if (*(p+1) == 0x81 ||
                    *(p+1) == 0x82 ||
                    *(p+1) == 0x83)
                    isoclns_print(ndo, p + 1, length - 1, ndo->ndo_snapend - p - 1);
                else
                    isoclns_print(ndo, p, length, ndo->ndo_snapend - p);
                break;
	default:
                if (!ndo->ndo_eflag)
                        ND_PRINT((ndo, "unknown CHDLC protocol (0x%04x)", proto));
                break;
	}

	return (CHDLC_HDRLEN);

trunc:
	ND_PRINT((ndo, "[|chdlc]"));
	return ndo->ndo_snapend - bp;
}

/*
 * The fixed-length portion of a SLARP packet.
 */
struct cisco_slarp {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -97,9 +97,9 @@
                 if (*(p+1) == 0x81 ||
                     *(p+1) == 0x82 ||
                     *(p+1) == 0x83)
-                    isoclns_print(ndo, p + 1, length - 1, ndo->ndo_snapend - p - 1);
+                    isoclns_print(ndo, p + 1, length - 1);
                 else
-                    isoclns_print(ndo, p, length, ndo->ndo_snapend - p);
+                    isoclns_print(ndo, p, length);
                 break;
 	default:
                 if (!ndo->ndo_eflag)
```
