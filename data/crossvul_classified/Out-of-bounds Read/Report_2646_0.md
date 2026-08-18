# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2646_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2646_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 525-565 of the vulnerable file.

	length = pktlen;

	rhp = (const union routehdr *)&(ap[sizeof(short)]);
	ND_TCHECK(rhp->rh_short.sh_flags);
	mflags = EXTRACT_LE_8BITS(rhp->rh_short.sh_flags);

	if (mflags & RMF_PAD) {
	    /* pad bytes of some sort in front of message */
	    u_int padlen = mflags & RMF_PADMASK;
	    if (ndo->ndo_vflag)
		ND_PRINT((ndo, "[pad:%d] ", padlen));
	    if (length < padlen + 2) {
		ND_PRINT((ndo, "%s", tstr));
		return;
	    }
	    ND_TCHECK2(ap[sizeof(short)], padlen);
	    ap += padlen;
	    length -= padlen;
	    caplen -= padlen;
	    rhp = (const union routehdr *)&(ap[sizeof(short)]);
	    mflags = EXTRACT_LE_8BITS(rhp->rh_short.sh_flags);
	}

	if (mflags & RMF_FVER) {
		ND_PRINT((ndo, "future-version-decnet"));
		ND_DEFAULTPRINT(ap, min(length, caplen));
		return;
	}

	/* is it a control message? */
	if (mflags & RMF_CTLMSG) {
		if (!print_decnet_ctlmsg(ndo, rhp, length, caplen))
			goto trunc;
		return;
	}

	switch (mflags & RMF_MASK) {
	case RMF_LONG:
	    if (length < sizeof(struct longhdr)) {
		ND_PRINT((ndo, "%s", tstr));
		return;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -542,6 +542,7 @@
 	    length -= padlen;
 	    caplen -= padlen;
 	    rhp = (const union routehdr *)&(ap[sizeof(short)]);
+	    ND_TCHECK(rhp->rh_short.sh_flags);
 	    mflags = EXTRACT_LE_8BITS(rhp->rh_short.sh_flags);
 	}
 
@@ -613,6 +614,7 @@
                     register const union routehdr *rhp, u_int length,
                     u_int caplen)
 {
+	/* Our caller has already checked for mflags */
 	int mflags = EXTRACT_LE_8BITS(rhp->rh_short.sh_flags);
 	register const union controlmsg *cmp = (const union controlmsg *)rhp;
 	int src, dst, info, blksize, eco, ueco, hello, other, vers;
```
