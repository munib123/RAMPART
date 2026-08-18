# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2669_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2669_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 713-753 of the vulnerable file.

	}

	switch (PIM_TYPE(pim->pim_typever)) {
	case PIMV2_TYPE_HELLO:
	    {
		uint16_t otype, olen;
		bp += 4;
		while (bp < ep) {
			ND_TCHECK2(bp[0], 4);
			otype = EXTRACT_16BITS(&bp[0]);
			olen = EXTRACT_16BITS(&bp[2]);
			ND_TCHECK2(bp[0], 4 + olen);
			ND_PRINT((ndo, "\n\t  %s Option (%u), length %u, Value: ",
			          tok2str(pimv2_hello_option_values, "Unknown", otype),
			          otype,
			          olen));
			bp += 4;

			switch (otype) {
			case PIMV2_HELLO_OPTION_HOLDTIME:
				unsigned_relts_print(ndo, EXTRACT_16BITS(bp));
				break;

			case PIMV2_HELLO_OPTION_LANPRUNEDELAY:
				if (olen != 4) {
					ND_PRINT((ndo, "ERROR: Option Length != 4 Bytes (%u)", olen));
				} else {
					char t_bit;
					uint16_t lan_delay, override_interval;
					lan_delay = EXTRACT_16BITS(bp);
					override_interval = EXTRACT_16BITS(bp+2);
					t_bit = (lan_delay & 0x8000)? 1 : 0;
					lan_delay &= ~0x8000;
					ND_PRINT((ndo, "\n\t    T-bit=%d, LAN delay %dms, Override interval %dms",
					t_bit, lan_delay, override_interval));
				}
				break;

			case PIMV2_HELLO_OPTION_DR_PRIORITY_OLD:
			case PIMV2_HELLO_OPTION_DR_PRIORITY:
				switch (olen) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -730,7 +730,11 @@
 
 			switch (otype) {
 			case PIMV2_HELLO_OPTION_HOLDTIME:
-				unsigned_relts_print(ndo, EXTRACT_16BITS(bp));
+				if (olen != 2) {
+					ND_PRINT((ndo, "ERROR: Option Length != 2 Bytes (%u)", olen));
+				} else {
+					unsigned_relts_print(ndo, EXTRACT_16BITS(bp));
+				}
 				break;
 
 			case PIMV2_HELLO_OPTION_LANPRUNEDELAY:
@@ -764,17 +768,25 @@
 				break;
 
 			case PIMV2_HELLO_OPTION_GENID:
-				ND_PRINT((ndo, "0x%08x", EXTRACT_32BITS(bp)));
+				if (olen != 4) {
+					ND_PRINT((ndo, "ERROR: Option Length != 4 Bytes (%u)", olen));
+				} else {
+					ND_PRINT((ndo, "0x%08x", EXTRACT_32BITS(bp)));
+				}
 				break;
 
 			case PIMV2_HELLO_OPTION_REFRESH_CAP:
-				ND_PRINT((ndo, "v%d", *bp));
-				if (*(bp+1) != 0) {
-					ND_PRINT((ndo, ", interval "));
-					unsigned_relts_print(ndo, *(bp+1));
-				}
-				if (EXTRACT_16BITS(bp+2) != 0) {
-					ND_PRINT((ndo, " ?0x%04x?", EXTRACT_16BITS(bp+2)));
+				if (olen != 4) {
+					ND_PRINT((ndo, "ERROR: Option Length != 4 Bytes (%u)", olen));
+				} else {
+					ND_PRINT((ndo, "v%d", *bp));
+					if (*(bp+1) != 0) {
+						ND_PRINT((ndo, ", interval "));
+						unsigned_relts_print(ndo, *(bp+1));
+					}
+					if (EXTRACT_16BITS(bp+2) != 0) {
+						ND_PRINT((ndo, " ?0x%04x?", EXTRACT_16BITS(bp+2)));
+					}
 				}
 				break;
 
```
