# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2643_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2643_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 3024-3064 of the vulnerable file.

		hexprint(ndo, (const uint8_t *)&base.r_ck, sizeof(base.r_ck));
	}
	ND_PRINT((ndo,":"));

	switch(major) {
	case IKEv1_MAJOR_VERSION:
		ikev1_print(ndo, bp, length, bp2, &base);
		break;

	case IKEv2_MAJOR_VERSION:
		ikev2_print(ndo, bp, length, bp2, &base);
		break;
	}
}

void
isakmp_rfc3948_print(netdissect_options *ndo,
		     const u_char *bp, u_int length,
		     const u_char *bp2)
{

	if(length == 1 && bp[0]==0xff) {
		ND_PRINT((ndo, "isakmp-nat-keep-alive"));
		return;
	}

	if(length < 4) {
		goto trunc;
	}

	/*
	 * see if this is an IKE packet
	 */
	if(bp[0]==0 && bp[1]==0 && bp[2]==0 && bp[3]==0) {
		ND_PRINT((ndo, "NONESP-encap: "));
		isakmp_print(ndo, bp+4, length-4, bp2);
		return;
	}

	/* must be an ESP packet */
	{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3041,7 +3041,7 @@
 		     const u_char *bp, u_int length,
 		     const u_char *bp2)
 {
-
+	ND_TCHECK(bp[0]);
 	if(length == 1 && bp[0]==0xff) {
 		ND_PRINT((ndo, "isakmp-nat-keep-alive"));
 		return;
@@ -3050,6 +3050,7 @@
 	if(length < 4) {
 		goto trunc;
 	}
+	ND_TCHECK(bp[3]);
 
 	/*
 	 * see if this is an IKE packet
```
