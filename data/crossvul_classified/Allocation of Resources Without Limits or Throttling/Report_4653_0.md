# CrossVul Fix Pair: Allocation of Resources Without Limits or Throttling in c
**Pair ID:** 4653_0
**Vulnerability Class:** Allocation of Resources Without Limits or Throttling
**CWE:** CWE-770
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4653_0`)

## Vulnerability Information & PoC

## Description
Allocation of Resources Without Limits or Throttling - Code frequently has to work with limited resources, so programmers must be careful to ensure that resources are not consumed too quickly, or too easily.

## Vulnerable Code
```c
Lines 1350-1390 of the vulnerable file.

		break;
	default:
		/*
		 * Unknown option; dump it as raw bytes now if we're
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
	u_char *b, *t, c;
	const u_char *s;
	int i, proto;
	const void *se;

        if (length <= 0)
                return;

	b = (u_char *)malloc(length);
	if (b == NULL)
		return;

	/*
	 * Unescape all the data into a temporary, private, buffer.
	 * Do this so that we dont overwrite the original packet
	 * contents.
	 */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1367,19 +1367,29 @@
 	return 0;
 }
 
+/*
+ * Un-escape RFC 1662 PPP in HDLC-like framing, with octet escapes.
+ * The length argument is the on-the-wire length, not the captured
+ * length; we can only un-escape the captured part.
+ */
 static void
 ppp_hdlc(netdissect_options *ndo,
          const u_char *p, int length)
 {
+	u_int caplen = ndo->ndo_snapend - p;
 	u_char *b, *t, c;
 	const u_char *s;
-	int i, proto;
+	u_int i;
+	int proto;
 	const void *se;
+
+	if (caplen == 0)
+		return;
 
         if (length <= 0)
                 return;
 
-	b = (u_char *)malloc(length);
+	b = (u_char *)malloc(caplen);
 	if (b == NULL)
 		return;
 
@@ -1388,10 +1398,10 @@
 	 * Do this so that we dont overwrite the original packet
 	 * contents.
 	 */
-	for (s = p, t = b, i = length; i > 0 && ND_TTEST(*s); i--) {
+	for (s = p, t = b, i = caplen; i != 0; i--) {
 		c = *s++;
 		if (c == 0x7d) {
-			if (i <= 1 || !ND_TTEST(*s))
+			if (i <= 1)
 				break;
 			i--;
 			c = *s++ ^ 0x20;
```
