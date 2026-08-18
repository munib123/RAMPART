# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5727_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5727_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 383-423 of the vulnerable file.

 * 	process - 
 *		Process a compression code.  "clear" resets the code table.  
 *	Otherwise make a new code table entry, and output the bytes 
 *	associated with the code.
 */
int
process(register int code, unsigned char** fill)
{
    int incode;
    static unsigned char firstchar;

    if (code == clear) {
	codesize = datasize + 1;
	codemask = (1 << codesize) - 1;
	avail = clear + 2;
	oldcode = -1;
	return 1;
    }

    if (oldcode == -1) {
	*(*fill)++ = suffix[code];
	firstchar = oldcode = code;
	return 1;
    }
    if (code > avail) {
	fprintf(stderr, "code %d too large for %d\n", code, avail);
	return 0; 
    }

    incode = code;
    if (code == avail) {      /* the first code is always < avail */
	*stackp++ = firstchar;
	code = oldcode;
    }
    while (code > clear) {
	*stackp++ = suffix[code];
	code = prefix[code];
    }

    *stackp++ = firstchar = suffix[code];
    prefix[avail] = oldcode;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -400,6 +400,10 @@
     }
 
     if (oldcode == -1) {
+        if (code >= clear) {
+            fprintf(stderr, "bad input: code=%d is larger than clear=%d\n",code, clear);
+            return 0;
+        }
 	*(*fill)++ = suffix[code];
 	firstchar = oldcode = code;
 	return 1;
```
