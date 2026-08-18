# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2686_3
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2686_3`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 506-547 of the vulnerable file.

	register u_int v)
{
	static char buf[4][TOKBUFSIZE];
	static int idx = 0;
	char *ret;

	ret = buf[idx];
	idx = (idx+1) & 3;
	return tok2strbuf(lp, fmt, v, ret, sizeof(buf[0]));
}

/*
 * Convert a bit token value to a string; use "fmt" if not found.
 * this is useful for parsing bitfields, the output strings are seperated
 * if the s field is positive.
 */
static char *
bittok2str_internal(register const struct tok *lp, register const char *fmt,
	   register u_int v, const char *sep)
{
        static char buf[256]; /* our stringbuffer */
        int buflen=0;
        register u_int rotbit; /* this is the bit we rotate through all bitpositions */
        register u_int tokval;
        const char * sepstr = "";

	while (lp != NULL && lp->s != NULL) {
            tokval=lp->v;   /* load our first value */
            rotbit=1;
            while (rotbit != 0) {
                /*
                 * lets AND the rotating bit with our token value
                 * and see if we have got a match
                 */
		if (tokval == (v&rotbit)) {
                    /* ok we have found something */
                    buflen+=snprintf(buf+buflen, sizeof(buf)-buflen, "%s%s",
                                     sepstr, lp->s);
                    sepstr = sep;
                    break;
                }
                rotbit=rotbit<<1; /* no match - lets shift and try again */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -523,8 +523,9 @@
 bittok2str_internal(register const struct tok *lp, register const char *fmt,
 	   register u_int v, const char *sep)
 {
-        static char buf[256]; /* our stringbuffer */
-        int buflen=0;
+        static char buf[1024+1]; /* our string buffer */
+        char *bufp = buf;
+        size_t space_left = sizeof(buf), string_size;
         register u_int rotbit; /* this is the bit we rotate through all bitpositions */
         register u_int tokval;
         const char * sepstr = "";
@@ -539,8 +540,20 @@
                  */
 		if (tokval == (v&rotbit)) {
                     /* ok we have found something */
-                    buflen+=snprintf(buf+buflen, sizeof(buf)-buflen, "%s%s",
-                                     sepstr, lp->s);
+                    if (space_left <= 1)
+                        return (buf); /* only enough room left for NUL, if that */
+                    string_size = strlcpy(bufp, sepstr, space_left);
+                    if (string_size >= space_left)
+                        return (buf);    /* we ran out of room */
+                    bufp += string_size;
+                    space_left -= string_size;
+                    if (space_left <= 1)
+                        return (buf); /* only enough room left for NUL, if that */
+                    string_size = strlcpy(bufp, lp->s, space_left);
+                    if (string_size >= space_left)
+                        return (buf);    /* we ran out of room */
+                    bufp += string_size;
+                    space_left -= string_size;
                     sepstr = sep;
                     break;
                 }
@@ -549,7 +562,7 @@
             lp++;
 	}
 
-        if (buflen == 0)
+        if (bufp == buf)
             /* bummer - lets print the "unknown" message as advised in the fmt string if we got one */
             (void)snprintf(buf, sizeof(buf), fmt == NULL ? "#%08x" : fmt, v);
         return (buf);
```
