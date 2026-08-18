# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2639_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2639_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 220-260 of the vulnerable file.

 * return the total storage length of a mangled name
 */
static int
name_len(netdissect_options *ndo,
         const unsigned char *s, const unsigned char *maxbuf)
{
    const unsigned char *s0 = s;
    unsigned char c;

    if (s >= maxbuf)
	return(-1);	/* name goes past the end of the buffer */
    ND_TCHECK2(*s, 1);
    c = *s;
    if ((c & 0xC0) == 0xC0)
	return(2);
    while (*s) {
	if (s >= maxbuf)
	    return(-1);	/* name goes past the end of the buffer */
	ND_TCHECK2(*s, 1);
	s += (*s) + 1;
    }
    return(PTR_DIFF(s, s0) + 1);

trunc:
    return(-1);	/* name goes past the end of the buffer */
}

static void
print_asc(netdissect_options *ndo,
          const unsigned char *buf, int len)
{
    int i;
    for (i = 0; i < len; i++)
        safeputchar(ndo, buf[i]);
}

static const char *
name_type_str(int name_type)
{
    const char *f = NULL;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -237,6 +237,7 @@
 	    return(-1);	/* name goes past the end of the buffer */
 	ND_TCHECK2(*s, 1);
 	s += (*s) + 1;
+	ND_TCHECK2(*s, 1);
     }
     return(PTR_DIFF(s, s0) + 1);
 
```
