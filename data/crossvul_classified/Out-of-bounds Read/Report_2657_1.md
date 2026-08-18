# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2657_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2657_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 315-336 of the vulnerable file.

		ND_PRINT((ndo, " status=%u", mh->ip6m_data8[0]));
		/* Reserved */
		hlen = IP6M_MINLEN;
		ND_TCHECK2(*mh, hlen + 16);
		ND_PRINT((ndo, " homeaddr %s", ip6addr_string(ndo, &bp[hlen])));
		hlen += 16;
		break;
	default:
		ND_PRINT((ndo, " len=%u", mh->ip6m_len));
		return(mhlen);
		break;
	}
	if (ndo->ndo_vflag)
		if (mobility_opt_print(ndo, &bp[hlen], mhlen - hlen))
			goto trunc;

	return(mhlen);

 trunc:
	ND_PRINT((ndo, "%s", tstr));
	return(mhlen);
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -332,5 +332,5 @@
 
  trunc:
 	ND_PRINT((ndo, "%s", tstr));
-	return(mhlen);
+	return(-1);
 }
```
