# CrossVul Fix Pair: Loop with Unreachable Exit Condition ('Infinite Loop') in c
**Pair ID:** 2668_0
**Vulnerability Class:** Loop with Unreachable Exit Condition ('Infinite Loop')
**CWE:** CWE-835
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2668_0`)

## Vulnerability Information & PoC

## Description
Loop with Unreachable Exit Condition ('Infinite Loop') - If the loop can be influenced by an attacker, this weakness could allow attackers to consume excessive resources such as CPU or memory.

## Vulnerable Code
```c
Lines 134-174 of the vulnerable file.

		if ((elt = (i & ~INDIR_MASK)) != EDNS0_ELT_BITLABEL) {
			ND_PRINT((ndo, "<ELT %d>", elt));
			return(-1);
		}
		if (!ND_TTEST2(*(cp + 1), 1))
			return(-1);
		if ((bitlen = *(cp + 1)) == 0)
			bitlen = 256;
		return(((bitlen + 7) / 8) + 1);
	} else
		return(i);
}

const u_char *
ns_nprint(netdissect_options *ndo,
          register const u_char *cp, register const u_char *bp)
{
	register u_int i, l;
	register const u_char *rp = NULL;
	register int compress = 0;
	int chars_processed;
	int elt;
	int data_size = ndo->ndo_snapend - bp;

	if ((l = labellen(ndo, cp)) == (u_int)-1)
		return(NULL);
	if (!ND_TTEST2(*cp, 1))
		return(NULL);
	chars_processed = 1;
	if (((i = *cp++) & INDIR_MASK) != INDIR_MASK) {
		compress = 0;
		rp = cp + l;
	}

	if (i != 0)
		while (i && cp < ndo->ndo_snapend) {
			if ((i & INDIR_MASK) == INDIR_MASK) {
				if (!compress) {
					rp = cp + 1;
					compress = 1;
				}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -151,15 +151,14 @@
 	register u_int i, l;
 	register const u_char *rp = NULL;
 	register int compress = 0;
-	int chars_processed;
 	int elt;
-	int data_size = ndo->ndo_snapend - bp;
+	u_int offset, max_offset;
 
 	if ((l = labellen(ndo, cp)) == (u_int)-1)
 		return(NULL);
 	if (!ND_TTEST2(*cp, 1))
 		return(NULL);
-	chars_processed = 1;
+	max_offset = (u_int)(cp - bp);
 	if (((i = *cp++) & INDIR_MASK) != INDIR_MASK) {
 		compress = 0;
 		rp = cp + l;
@@ -174,24 +173,28 @@
 				}
 				if (!ND_TTEST2(*cp, 1))
 					return(NULL);
-				cp = bp + (((i << 8) | *cp) & 0x3fff);
+				offset = (((i << 8) | *cp) & 0x3fff);
+				/*
+				 * This must move backwards in the packet.
+				 * No RFC explicitly says that, but BIND's
+				 * name decompression code requires it,
+				 * as a way of preventing infinite loops
+				 * and other bad behavior, and it's probably
+				 * what was intended (compress by pointing
+				 * to domain name suffixes already seen in
+				 * the packet).
+				 */
+				if (offset >= max_offset) {
+					ND_PRINT((ndo, "<BAD PTR>"));
+					return(NULL);
+				}
+				max_offset = offset;
+				cp = bp + offset;
 				if ((l = labellen(ndo, cp)) == (u_int)-1)
 					return(NULL);
 				if (!ND_TTEST2(*cp, 1))
 					return(NULL);
 				i = *cp++;
-				chars_processed++;
-
-				/*
-				 * If we've looked at every character in
-				 * the message, this pointer will make
-				 * us look at some character again,
-				 * which means we're looping.
-				 */
-				if (chars_processed >= data_size) {
-					ND_PRINT((ndo, "<LOOP>"));
-					return (NULL);
-				}
 				continue;
 			}
 			if ((i & INDIR_MASK) == EDNS0_MASK) {
@@ -212,14 +215,12 @@
 			}
 
 			cp += l;
-			chars_processed += l;
 			ND_PRINT((ndo, "."));
 			if ((l = labellen(ndo, cp)) == (u_int)-1)
 				return(NULL);
 			if (!ND_TTEST2(*cp, 1))
 				return(NULL);
 			i = *cp++;
-			chars_processed++;
 			if (!compress)
 				rp += l + 1;
 		}
```
