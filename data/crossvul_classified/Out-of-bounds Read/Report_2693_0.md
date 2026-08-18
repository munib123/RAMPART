# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2693_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2693_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 440-480 of the vulnerable file.

	    }
	    opt_len = *bp++;
	    if (opt_len != 4) {
		ND_PRINT((ndo, "[Bad OPT_LENGTH option, length %u != 4]", opt_len));
		return;
	    }
	    opts_len = EXTRACT_16BITS(bp);
	    if (opts_len < 4) {
		ND_PRINT((ndo, "[Bad total option length %u < 4]", opts_len));
		return;
	    }
	    bp += sizeof(uint16_t);
	    ND_PRINT((ndo, " OPTS LEN %d", opts_len));
	    opts_len -= 4;

	    while (opts_len) {
		if (opts_len < PGM_MIN_OPT_LEN) {
		    ND_PRINT((ndo, "[Total option length leaves no room for final option]"));
		    return;
		}
		opt_type = *bp++;
		opt_len = *bp++;
		if (opt_len < PGM_MIN_OPT_LEN) {
		    ND_PRINT((ndo, "[Bad option, length %u < %u]", opt_len,
		        PGM_MIN_OPT_LEN));
		    break;
		}
		if (opts_len < opt_len) {
		    ND_PRINT((ndo, "[Total option length leaves no room for final option]"));
		    return;
		}
		if (!ND_TTEST2(*bp, opt_len - 2)) {
		    ND_PRINT((ndo, " [|OPT]"));
		    return;
		}

		switch (opt_type & PGM_OPT_MASK) {
		case PGM_OPT_LENGTH:
		    if (opt_len != 4) {
			ND_PRINT((ndo, "[Bad OPT_LENGTH option, length %u != 4]", opt_len));
			return;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -457,6 +457,10 @@
 		    ND_PRINT((ndo, "[Total option length leaves no room for final option]"));
 		    return;
 		}
+		if (!ND_TTEST2(*bp, 2)) {
+		    ND_PRINT((ndo, " [|OPT]"));
+		    return;
+		}
 		opt_type = *bp++;
 		opt_len = *bp++;
 		if (opt_len < PGM_MIN_OPT_LEN) {
```
