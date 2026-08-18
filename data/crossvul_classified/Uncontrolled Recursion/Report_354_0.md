# CrossVul Fix Pair: Uncontrolled Recursion in c
**Pair ID:** 354_0
**Vulnerability Class:** Uncontrolled Recursion
**CWE:** CWE-674
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `354_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Recursion - The product does not properly control the amount of recursion that takes place, consuming excessive resources, such as allocated memory or the program stack.

## Vulnerable Code
```c
Lines 790-830 of the vulnerable file.

    ND_PRINT((ndo, "WARNING: Short packet. Try increasing the snap length\n"));
    return(NULL);
}

const u_char *
smb_fdata(netdissect_options *ndo,
          const u_char *buf, const char *fmt, const u_char *maxbuf,
          int unicodestr)
{
    static int depth = 0;
    char s[128];
    char *p;

    while (*fmt) {
	switch (*fmt) {
	case '*':
	    fmt++;
	    while (buf < maxbuf) {
		const u_char *buf2;
		depth++;
		buf2 = smb_fdata(ndo, buf, fmt, maxbuf, unicodestr);
		depth--;
		if (buf2 == NULL)
		    return(NULL);
		if (buf2 == buf)
		    return(buf);
		buf = buf2;
	    }
	    return(buf);

	case '|':
	    fmt++;
	    if (buf >= maxbuf)
		return(buf);
	    break;

	case '%':
	    fmt++;
	    buf = maxbuf;
	    break;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -807,7 +807,14 @@
 	    while (buf < maxbuf) {
 		const u_char *buf2;
 		depth++;
-		buf2 = smb_fdata(ndo, buf, fmt, maxbuf, unicodestr);
+		/* Not sure how this relates with the protocol specification,
+		 * but in order to avoid stack exhaustion recurse at most that
+		 * many levels.
+		 */
+		if (depth == 10)
+			ND_PRINT((ndo, "(too many nested levels, not recursing)"));
+		else
+			buf2 = smb_fdata(ndo, buf, fmt, maxbuf, unicodestr);
 		depth--;
 		if (buf2 == NULL)
 		    return(NULL);
```
