# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2645_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2645_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 611-651 of the vulnerable file.

		    (dp = parsefh(ndo, dp, v3)) != NULL) {
			if (v3) {
				ND_TCHECK(dp[2]);
				ND_PRINT((ndo, " %u bytes @ %" PRIu64,
				       EXTRACT_32BITS(&dp[2]),
				       EXTRACT_64BITS(&dp[0])));
			} else {
				ND_TCHECK(dp[1]);
				ND_PRINT((ndo, " %u bytes @ %u",
				    EXTRACT_32BITS(&dp[1]),
				    EXTRACT_32BITS(&dp[0])));
			}
			return;
		}
		break;

	case NFSPROC_WRITE:
		if ((dp = parsereq(ndo, rp, length)) != NULL &&
		    (dp = parsefh(ndo, dp, v3)) != NULL) {
			if (v3) {
				ND_TCHECK(dp[2]);
				ND_PRINT((ndo, " %u (%u) bytes @ %" PRIu64,
						EXTRACT_32BITS(&dp[4]),
						EXTRACT_32BITS(&dp[2]),
						EXTRACT_64BITS(&dp[0])));
				if (ndo->ndo_vflag) {
					dp += 3;
					ND_TCHECK(dp[0]);
					ND_PRINT((ndo, " <%s>",
						tok2str(nfsv3_writemodes,
							NULL, EXTRACT_32BITS(dp))));
				}
			} else {
				ND_TCHECK(dp[3]);
				ND_PRINT((ndo, " %u (%u) bytes @ %u (%u)",
						EXTRACT_32BITS(&dp[3]),
						EXTRACT_32BITS(&dp[2]),
						EXTRACT_32BITS(&dp[1]),
						EXTRACT_32BITS(&dp[0])));
			}
			return;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -628,17 +628,15 @@
 		if ((dp = parsereq(ndo, rp, length)) != NULL &&
 		    (dp = parsefh(ndo, dp, v3)) != NULL) {
 			if (v3) {
-				ND_TCHECK(dp[2]);
+				ND_TCHECK(dp[4]);
 				ND_PRINT((ndo, " %u (%u) bytes @ %" PRIu64,
 						EXTRACT_32BITS(&dp[4]),
 						EXTRACT_32BITS(&dp[2]),
 						EXTRACT_64BITS(&dp[0])));
 				if (ndo->ndo_vflag) {
-					dp += 3;
-					ND_TCHECK(dp[0]);
 					ND_PRINT((ndo, " <%s>",
 						tok2str(nfsv3_writemodes,
-							NULL, EXTRACT_32BITS(dp))));
+							NULL, EXTRACT_32BITS(&dp[3]))));
 				}
 			} else {
 				ND_TCHECK(dp[3]);
@@ -1002,11 +1000,11 @@
 	 * skip past the ar_verf credentials.
 	 */
 	dp += (len + (2*sizeof(uint32_t) + 3)) / sizeof(uint32_t);
-	ND_TCHECK2(dp[0], 0);
 
 	/*
 	 * now we can check the ar_stat field
 	 */
+	ND_TCHECK(dp[0]);
 	astat = (enum sunrpc_accept_stat) EXTRACT_32BITS(dp);
 	if (astat != SUNRPC_SUCCESS) {
 		ND_PRINT((ndo, " %s", tok2str(sunrpc_str, "ar_stat %d", astat)));
@@ -1243,6 +1241,7 @@
 parse_wcc_attr(netdissect_options *ndo,
                const uint32_t *dp)
 {
+	/* Our caller has already checked this */
 	ND_PRINT((ndo, " sz %" PRIu64, EXTRACT_64BITS(&dp[0])));
 	ND_PRINT((ndo, " mtime %u.%06u ctime %u.%06u",
 	       EXTRACT_32BITS(&dp[2]), EXTRACT_32BITS(&dp[3]),
@@ -1511,8 +1510,10 @@
 			ND_PRINT((ndo, " attr:"));
 		if (!(dp = parse_post_op_attr(ndo, dp, ndo->ndo_vflag)))
 			break;
-		if (!er)
+		if (!er) {
+			ND_TCHECK(dp[0]);
 			ND_PRINT((ndo, " c %04x", EXTRACT_32BITS(&dp[0])));
+		}
 		return;
 
 	case NFSPROC_READLINK:
```
