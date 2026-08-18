# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 267_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `267_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1752-1792 of the vulnerable file.


	if (cp < ep) {
		switch (ntohs(n.type)) {
		case IPSECDOI_NTYPE_RESPONDER_LIFETIME:
		    {
			const struct attrmap *map = oakley_t_map;
			size_t nmap = sizeof(oakley_t_map)/sizeof(oakley_t_map[0]);
			ND_PRINT((ndo," attrs=("));
			while (cp < ep && cp < ep2) {
				cp = ikev1_attrmap_print(ndo, cp, ep2, map, nmap);
				if (cp == NULL) {
					ND_PRINT((ndo,")"));
					goto trunc;
				}
			}
			ND_PRINT((ndo,")"));
			break;
		    }
		case IPSECDOI_NTYPE_REPLAY_STATUS:
			ND_PRINT((ndo," status=("));
			ND_PRINT((ndo,"replay detection %sabled",
				  EXTRACT_32BITS(cp) ? "en" : "dis"));
			ND_PRINT((ndo,")"));
			break;
		default:
			/*
			 * XXX - fill in more types here; see, for example,
			 * draft-ietf-ipsec-notifymsg-04.
			 */
			if (ndo->ndo_vflag > 3) {
				ND_PRINT((ndo," data=("));
				if (!rawprint(ndo, (const uint8_t *)(cp), ep - cp))
					goto trunc;
				ND_PRINT((ndo,")"));
			} else {
				if (!ike_show_somedata(ndo, cp, ep))
					goto trunc;
			}
			break;
		}
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1769,6 +1769,7 @@
 		    }
 		case IPSECDOI_NTYPE_REPLAY_STATUS:
 			ND_PRINT((ndo," status=("));
+			ND_TCHECK_32BITS(cp);
 			ND_PRINT((ndo,"replay detection %sabled",
 				  EXTRACT_32BITS(cp) ? "en" : "dis"));
 			ND_PRINT((ndo,")"));
```
