# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2353_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2353_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1334-1374 of the vulnerable file.

		 * not going to do so below.
		 */
		if (ndo->ndo_vflag < 2)
			print_unknown_data(ndo, &p[2], "\n\t    ", len - 2);
		break;
	}
	if (ndo->ndo_vflag > 1)
		print_unknown_data(ndo, &p[2], "\n\t    ", len - 2); /* exclude TLV header */

	return len;

trunc:
	ND_PRINT((ndo, "[|bacp]"));
	return 0;
}

static void
ppp_hdlc(netdissect_options *ndo,
         const u_char *p, int length)
{
	u_char *b, *s, *t, c;
	int i, proto;
	const void *se;

        if (length <= 0)
                return;

	b = (uint8_t *)malloc(length);
	if (b == NULL)
		return;

	/*
	 * Unescape all the data into a temporary, private, buffer.
	 * Do this so that we dont overwrite the original packet
	 * contents.
	 */
	for (s = (u_char *)p, t = b, i = length; i > 0; i--) {
		c = *s++;
		if (c == 0x7d) {
			if (i > 1) {
				i--;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1351,14 +1351,15 @@
 ppp_hdlc(netdissect_options *ndo,
          const u_char *p, int length)
 {
-	u_char *b, *s, *t, c;
+	u_char *b, *t, c;
+	const u_char *s;
 	int i, proto;
 	const void *se;
 
         if (length <= 0)
                 return;
 
-	b = (uint8_t *)malloc(length);
+	b = (u_char *)malloc(length);
 	if (b == NULL)
 		return;
 
@@ -1367,14 +1368,13 @@
 	 * Do this so that we dont overwrite the original packet
 	 * contents.
 	 */
-	for (s = (u_char *)p, t = b, i = length; i > 0; i--) {
+	for (s = p, t = b, i = length; i > 0 && ND_TTEST(*s); i--) {
 		c = *s++;
 		if (c == 0x7d) {
-			if (i > 1) {
-				i--;
-				c = *s++ ^ 0x20;
-			} else
-				continue;
+			if (i <= 1 || !ND_TTEST(*s))
+				break;
+			i--;
+			c = *s++ ^ 0x20;
 		}
 		*t++ = c;
 	}
```
