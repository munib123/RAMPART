# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2644_4
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2644_4`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 312-352 of the vulnerable file.

		goto trunc;
	nlpid = p[hdr_len - 1];

	if (ndo->ndo_eflag)
		fr_hdr_print(ndo, length, addr_len, dlci, flags, nlpid);
	p += hdr_len;
	length -= hdr_len;

	switch (nlpid) {
	case NLPID_IP:
	        ip_print(ndo, p, length);
		break;

	case NLPID_IP6:
		ip6_print(ndo, p, length);
		break;

	case NLPID_CLNP:
	case NLPID_ESIS:
	case NLPID_ISIS:
		isoclns_print(ndo, p - 1, length + 1, ndo->ndo_snapend - p + 1); /* OSI printers need the NLPID field */
		break;

	case NLPID_SNAP:
		if (snap_print(ndo, p, length, ndo->ndo_snapend - p, NULL, NULL, 0) == 0) {
			/* ether_type not known, print raw packet */
                        if (!ndo->ndo_eflag)
                            fr_hdr_print(ndo, length + hdr_len, hdr_len,
                                         dlci, flags, nlpid);
			if (!ndo->ndo_suppress_default_print)
				ND_DEFAULTPRINT(p - hdr_len, length + hdr_len);
		}
		break;

        case NLPID_Q933:
		q933_print(ndo, p, length);
		break;

        case NLPID_MFR:
                frf15_print(ndo, p, length);
                break;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -329,7 +329,7 @@
 	case NLPID_CLNP:
 	case NLPID_ESIS:
 	case NLPID_ISIS:
-		isoclns_print(ndo, p - 1, length + 1, ndo->ndo_snapend - p + 1); /* OSI printers need the NLPID field */
+		isoclns_print(ndo, p - 1, length + 1); /* OSI printers need the NLPID field */
 		break;
 
 	case NLPID_SNAP:
```
