# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2644_8
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2644_8`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 307-347 of the vulnerable file.


#ifdef ENABLE_SMB
	if (ssap == LLCSAP_NETBEUI && dsap == LLCSAP_NETBEUI
	    && (!(control & LLC_S_FMT) || control == LLC_U_FMT)) {
		/*
		 * we don't actually have a full netbeui parser yet, but the
		 * smb parser can handle many smb-in-netbeui packets, which
		 * is very useful, so we call that
		 *
		 * We don't call it for S frames, however, just I frames
		 * (which are frames that don't have the low-order bit,
		 * LLC_S_FMT, set in the first byte of the control field)
		 * and UI frames (whose control field is just 3, LLC_U_FMT).
		 */
		netbeui_print(ndo, control, p, length);
		return (hdrlen);
	}
#endif
	if (ssap == LLCSAP_ISONS && dsap == LLCSAP_ISONS
	    && control == LLC_UI) {
		isoclns_print(ndo, p, length, caplen);
		return (hdrlen);
	}

	if (!ndo->ndo_eflag) {
		if (ssap == dsap) {
			if (src == NULL || dst == NULL)
				ND_PRINT((ndo, "%s ", tok2str(llc_values, "Unknown DSAP 0x%02x", dsap)));
			else
				ND_PRINT((ndo, "%s > %s %s ",
						(src->addr_string)(ndo, src->addr),
						(dst->addr_string)(ndo, dst->addr),
						tok2str(llc_values, "Unknown DSAP 0x%02x", dsap)));
		} else {
			if (src == NULL || dst == NULL)
				ND_PRINT((ndo, "%s > %s ",
                                        tok2str(llc_values, "Unknown SSAP 0x%02x", ssap),
					tok2str(llc_values, "Unknown DSAP 0x%02x", dsap)));
			else
				ND_PRINT((ndo, "%s %s > %s %s ",
					(src->addr_string)(ndo, src->addr),
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -324,7 +324,7 @@
 #endif
 	if (ssap == LLCSAP_ISONS && dsap == LLCSAP_ISONS
 	    && control == LLC_UI) {
-		isoclns_print(ndo, p, length, caplen);
+		isoclns_print(ndo, p, length);
 		return (hdrlen);
 	}
 
```
