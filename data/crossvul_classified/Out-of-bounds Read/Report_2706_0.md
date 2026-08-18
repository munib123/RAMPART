# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2706_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2706_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 594-634 of the vulnerable file.

		if ((opt >= LCPOPT_MIN) && (opt <= LCPOPT_MAX))
			ND_PRINT((ndo, "\n\t  %s Option (0x%02x), length %u (length bogus, should be >= 2)",
			          lcpconfopts[opt], opt, len));
		else
			ND_PRINT((ndo, "\n\tunknown LCP option 0x%02x", opt));
		return 0;
	}
	if ((opt >= LCPOPT_MIN) && (opt <= LCPOPT_MAX))
		ND_PRINT((ndo, "\n\t  %s Option (0x%02x), length %u", lcpconfopts[opt], opt, len));
	else {
		ND_PRINT((ndo, "\n\tunknown LCP option 0x%02x", opt));
		return len;
	}

	switch (opt) {
	case LCPOPT_VEXT:
		if (len < 6) {
			ND_PRINT((ndo, " (length bogus, should be >= 6)"));
			return len;
		}
		ND_TCHECK2(*(p + 2), 3);
		ND_PRINT((ndo, ": Vendor: %s (%u)",
			tok2str(oui_values,"Unknown",EXTRACT_24BITS(p+2)),
			EXTRACT_24BITS(p + 2)));
#if 0
		ND_TCHECK(p[5]);
		ND_PRINT((ndo, ", kind: 0x%02x", p[5]));
		ND_PRINT((ndo, ", Value: 0x"));
		for (i = 0; i < len - 6; i++) {
			ND_TCHECK(p[6 + i]);
			ND_PRINT((ndo, "%02x", p[6 + i]));
		}
#endif
		break;
	case LCPOPT_MRU:
		if (len != 4) {
			ND_PRINT((ndo, " (length bogus, should be = 4)"));
			return len;
		}
		ND_TCHECK2(*(p + 2), 2);
		ND_PRINT((ndo, ": %u", EXTRACT_16BITS(p + 2)));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -611,7 +611,7 @@
 			ND_PRINT((ndo, " (length bogus, should be >= 6)"));
 			return len;
 		}
-		ND_TCHECK2(*(p + 2), 3);
+		ND_TCHECK_24BITS(p + 2);
 		ND_PRINT((ndo, ": Vendor: %s (%u)",
 			tok2str(oui_values,"Unknown",EXTRACT_24BITS(p+2)),
 			EXTRACT_24BITS(p + 2)));
@@ -630,7 +630,7 @@
 			ND_PRINT((ndo, " (length bogus, should be = 4)"));
 			return len;
 		}
-		ND_TCHECK2(*(p + 2), 2);
+		ND_TCHECK_16BITS(p + 2);
 		ND_PRINT((ndo, ": %u", EXTRACT_16BITS(p + 2)));
 		break;
 	case LCPOPT_ACCM:
@@ -638,7 +638,7 @@
 			ND_PRINT((ndo, " (length bogus, should be = 6)"));
 			return len;
 		}
-		ND_TCHECK2(*(p + 2), 4);
+		ND_TCHECK_32BITS(p + 2);
 		ND_PRINT((ndo, ": 0x%08x", EXTRACT_32BITS(p + 2)));
 		break;
 	case LCPOPT_AP:
@@ -646,7 +646,7 @@
 			ND_PRINT((ndo, " (length bogus, should be >= 4)"));
 			return len;
 		}
-		ND_TCHECK2(*(p + 2), 2);
+		ND_TCHECK_16BITS(p + 2);
 		ND_PRINT((ndo, ": %s", tok2str(ppptype2str, "Unknown Auth Proto (0x04x)", EXTRACT_16BITS(p + 2))));
 
 		switch (EXTRACT_16BITS(p+2)) {
@@ -668,7 +668,7 @@
 			ND_PRINT((ndo, " (length bogus, should be >= 4)"));
 			return 0;
 		}
-		ND_TCHECK2(*(p + 2), 2);
+		ND_TCHECK_16BITS(p+2);
 		if (EXTRACT_16BITS(p+2) == PPP_LQM)
 			ND_PRINT((ndo, ": LQR"));
 		else
@@ -679,7 +679,7 @@
 			ND_PRINT((ndo, " (length bogus, should be = 6)"));
 			return 0;
 		}
-		ND_TCHECK2(*(p + 2), 4);
+		ND_TCHECK_32BITS(p + 2);
 		ND_PRINT((ndo, ": 0x%08x", EXTRACT_32BITS(p + 2)));
 		break;
 	case LCPOPT_PFC:
@@ -691,7 +691,7 @@
 			ND_PRINT((ndo, " (length bogus, should be = 4)"));
 			return 0;
 		}
-		ND_TCHECK2(*(p + 2), 2);
+		ND_TCHECK_16BITS(p + 2);
 		ND_PRINT((ndo, ": 0x%04x", EXTRACT_16BITS(p + 2)));
 		break;
 	case LCPOPT_CBACK:
@@ -710,7 +710,7 @@
 			ND_PRINT((ndo, " (length bogus, should be = 4)"));
 			return 0;
 		}
-		ND_TCHECK2(*(p + 2), 2);
+		ND_TCHECK_16BITS(p + 2);
 		ND_PRINT((ndo, ": %u", EXTRACT_16BITS(p + 2)));
 		break;
 	case LCPOPT_MLED:
@@ -1055,7 +1055,7 @@
 			ND_PRINT((ndo, " (length bogus, should be >= 4)"));
 			return 0;
 		}
-		ND_TCHECK2(*(p + 2), 2);
+		ND_TCHECK_16BITS(p+2);
 		compproto = EXTRACT_16BITS(p+2);
 
 		ND_PRINT((ndo, ": %s (0x%02x):",
@@ -1241,7 +1241,7 @@
 			ND_PRINT((ndo, " (length bogus, should be >= 3)"));
 			return len;
 		}
-		ND_TCHECK2(*(p + 2), 1);
+		ND_TCHECK(p[2]);
 		ND_PRINT((ndo, ": Version: %u, Dictionary Bits: %u",
 			p[2] >> 5, p[2] & 0x1f));
 		break;
@@ -1250,7 +1250,7 @@
 			ND_PRINT((ndo, " (length bogus, should be >= 4)"));
 			return len;
 		}
-		ND_TCHECK2(*(p + 2), 1);
+		ND_TCHECK(p[3]);
 		ND_PRINT((ndo, ": Features: %u, PxP: %s, History: %u, #CTX-ID: %u",
 				(p[2] & 0xc0) >> 6,
 				(p[2] & 0x20) ? "Enabled" : "Disabled",
@@ -1261,7 +1261,7 @@
 			ND_PRINT((ndo, " (length bogus, should be >= 4)"));
 			return len;
 		}
-		ND_TCHECK2(*(p + 2), 1);
+		ND_TCHECK(p[3]);
 		ND_PRINT((ndo, ": Window: %uK, Method: %s (0x%x), MBZ: %u, CHK: %u",
 			(p[2] & 0xf0) >> 4,
 			((p[2] & 0x0f) == 8) ? "zlib" : "unknown",
@@ -1336,7 +1336,7 @@
 			ND_PRINT((ndo, " (length bogus, should be = 6)"));
 			return len;
 		}
-		ND_TCHECK2(*(p + 2), 4);
+		ND_TCHECK_32BITS(p + 2);
 		ND_PRINT((ndo, ": Magic-Num 0x%08x", EXTRACT_32BITS(p + 2)));
 		break;
 	default:
```
