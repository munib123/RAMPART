# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2661_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2661_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 425-465 of the vulnerable file.

	case SB:
		/* DONT/DO/WONT/WILL x */
		FETCH(x, sp, length);
		if (x >= 0 && x < NTELOPTS) {
			if (print)
				ND_PRINT((ndo, "%s %s", telcmds[i], telopts[x]));
		} else {
			if (print)
				ND_PRINT((ndo, "%s %#x", telcmds[i], x));
		}
		if (c != SB)
			break;
		/* IAC SB .... IAC SE */
		p = sp;
		while (length > (u_int)(p + 1 - sp)) {
			ND_TCHECK2(*p, 2);
			if (p[0] == IAC && p[1] == SE)
				break;
			p++;
		}
		if (*p != IAC)
			goto pktend;

		switch (x) {
		case TELOPT_AUTHENTICATION:
			if (p <= sp)
				break;
			FETCH(c, sp, length);
			if (print)
				ND_PRINT((ndo, " %s", STR_OR_ID(c, authcmd)));
			if (p <= sp)
				break;
			FETCH(c, sp, length);
			if (print)
				ND_PRINT((ndo, " %s", STR_OR_ID(c, authtype)));
			break;
		case TELOPT_ENCRYPT:
			if (p <= sp)
				break;
			FETCH(c, sp, length);
			if (print)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -442,6 +442,7 @@
 				break;
 			p++;
 		}
+		ND_TCHECK(*p);
 		if (*p != IAC)
 			goto pktend;
 
```
