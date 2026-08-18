# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2717_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2717_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1682-1722 of the vulnerable file.

			ND_PRINT((ndo,", subject=%s",
                                  ipaddr_string(ndo, ni6 + 1)));
			break;
		default:
			ND_PRINT((ndo,", unknown subject"));
			break;
		}

		/*(*/
		ND_PRINT((ndo,")"));
		break;

	case ICMP6_NI_REPLY:
		if (icmp6len > siz) {
			ND_PRINT((ndo,"[|icmp6: node information reply]"));
			break;
		}

		needcomma = 0;

		ni6 = (const struct icmp6_nodeinfo *)dp;
		ND_PRINT((ndo," node information reply"));
		ND_PRINT((ndo," ("));	/*)*/
		switch (ni6->ni_code) {
		case ICMP6_NI_SUCCESS:
			if (ndo->ndo_vflag) {
				ND_PRINT((ndo,"success"));
				needcomma++;
			}
			break;
		case ICMP6_NI_REFUSED:
			ND_PRINT((ndo,"refused"));
			needcomma++;
			if (siz != sizeof(*ni6))
				if (ndo->ndo_vflag)
					ND_PRINT((ndo,", invalid length"));
			break;
		case ICMP6_NI_UNKNOWN:
			ND_PRINT((ndo,"unknown"));
			needcomma++;
			if (siz != sizeof(*ni6))
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1699,6 +1699,7 @@
 
 		needcomma = 0;
 
+		ND_TCHECK2(*dp, sizeof(*ni6));
 		ni6 = (const struct icmp6_nodeinfo *)dp;
 		ND_PRINT((ndo," node information reply"));
 		ND_PRINT((ndo," ("));	/*)*/
@@ -1753,6 +1754,7 @@
 				ND_PRINT((ndo,", "));
 			ND_PRINT((ndo,"DNS name"));
 			cp = (const u_char *)(ni6 + 1) + 4;
+			ND_TCHECK(cp[0]);
 			if (cp[0] == ep - cp - 1) {
 				/* icmp-name-lookup-03, pascal string */
 				if (ndo->ndo_vflag)
```
