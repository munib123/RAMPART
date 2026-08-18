# CrossVul Fix Pair: Uncontrolled Recursion in c
**Pair ID:** 333_0
**Vulnerability Class:** Uncontrolled Recursion
**CWE:** CWE-674
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `333_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Recursion - The product does not properly control the amount of recursion that takes place, consuming excessive resources, such as allocated memory or the program stack.

## Vulnerable Code
```c
Lines 1344-1384 of the vulnerable file.

     * If we correctly reached end of the AS path attribute data content,
     * then most likely ASs were indeed encoded as 2 bytes.
     */
    if (tptr == pptr + len) {
        return 2;
    }

trunc:

    /*
     * We can come here, either we did not have enough data, or if we
     * try to decode 4 byte ASs in 2 byte format. Either way, return 4,
     * so that calller can try to decode each AS as of 4 bytes. If indeed
     * there was not enough data, it will crib and end the parse anyways.
     */
   return 4;
}

static int
bgp_attr_print(netdissect_options *ndo,
               u_int atype, const u_char *pptr, u_int len)
{
	int i;
	uint16_t af;
	uint8_t safi, snpa, nhlen;
        union { /* copy buffer for bandwidth values */
            float f;
            uint32_t i;
        } bw;
	int advance;
	u_int tlen;
	const u_char *tptr;
	char buf[MAXHOSTNAMELEN + 100];
        int  as_size;

        tptr = pptr;
        tlen=len;

	switch (atype) {
	case BGPTYPE_ORIGIN:
		if (len != 1)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1361,7 +1361,7 @@
 
 static int
 bgp_attr_print(netdissect_options *ndo,
-               u_int atype, const u_char *pptr, u_int len)
+               u_int atype, const u_char *pptr, u_int len, const unsigned attr_set_level)
 {
 	int i;
 	uint16_t af;
@@ -2284,8 +2284,16 @@
                             ND_PRINT((ndo, "+%x", aflags & 0xf));
                         ND_PRINT((ndo, "]: "));
                     }
-                    /* FIXME check for recursion */
-                    if (!bgp_attr_print(ndo, atype, tptr, alen))
+                    /* The protocol encoding per se allows ATTR_SET to be nested as many times
+                     * as the message can accommodate. This printer used to be able to recurse
+                     * into ATTR_SET contents until the stack exhaustion, but now there is a
+                     * limit on that (if live protocol exchange goes that many levels deep,
+                     * something is probably wrong anyway). Feel free to refine this value if
+                     * you can find the spec with respective normative text.
+                     */
+                    if (attr_set_level == 10)
+                        ND_PRINT((ndo, "(too many nested levels, not recursing)"));
+                    else if (!bgp_attr_print(ndo, atype, tptr, alen, attr_set_level + 1))
                         return 0;
                     tptr += alen;
                     len -= alen;
@@ -2592,7 +2600,7 @@
 				goto trunc;
 			if (length < alen)
 				goto trunc;
-			if (!bgp_attr_print(ndo, atype, p, alen))
+			if (!bgp_attr_print(ndo, atype, p, alen, 0))
 				goto trunc;
 			p += alen;
 			len -= alen;
```
