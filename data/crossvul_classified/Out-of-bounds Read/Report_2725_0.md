# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2725_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2725_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 2560-2600 of the vulnerable file.

			ND_PRINT((ndo, " site"));
			UINTOUT();
			break;
		case 20000:		/* Begin */
		case 20001:		/* Commit */
		case 20007:		/* Abort */
		case 20008:		/* Release locks */
		case 20010:		/* Writev */
			ND_PRINT((ndo, " tid"));
			UBIK_VERSIONOUT();
			break;
		case 20002:		/* Lock */
			ND_PRINT((ndo, " tid"));
			UBIK_VERSIONOUT();
			ND_PRINT((ndo, " file"));
			INTOUT();
			ND_PRINT((ndo, " pos"));
			INTOUT();
			ND_PRINT((ndo, " length"));
			INTOUT();
			temp = EXTRACT_32BITS(bp);
			bp += sizeof(int32_t);
			tok2str(ubik_lock_types, "type %d", temp);
			break;
		case 20003:		/* Write */
			ND_PRINT((ndo, " tid"));
			UBIK_VERSIONOUT();
			ND_PRINT((ndo, " file"));
			INTOUT();
			ND_PRINT((ndo, " pos"));
			INTOUT();
			break;
		case 20005:		/* Get file */
			ND_PRINT((ndo, " file"));
			INTOUT();
			break;
		case 20006:		/* Send file */
			ND_PRINT((ndo, " file"));
			INTOUT();
			ND_PRINT((ndo, " length"));
			INTOUT();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2577,6 +2577,7 @@
 			INTOUT();
 			ND_PRINT((ndo, " length"));
 			INTOUT();
+			ND_TCHECK_32BITS(bp);
 			temp = EXTRACT_32BITS(bp);
 			bp += sizeof(int32_t);
 			tok2str(ubik_lock_types, "type %d", temp);
```
