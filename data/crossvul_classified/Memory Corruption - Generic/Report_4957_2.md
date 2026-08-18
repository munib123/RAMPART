# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 4957_2
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4957_2`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 30-70 of the vulnerable file.

    int chunk;
    UINT8* out;
    UINT8* ptr;

    ptr = buf;

    chunk = 3 * state->xsize;

    for (;;) {

	/* We need data for two full lines before we can do anything */
	if (bytes < chunk)
	    return ptr - buf;

	/* Unpack first line */
	out = state->buffer;
	for (x = 0; x < state->xsize; x++) {
	    out[0] = ptr[x];
	    out[1] = ptr[(x+4*state->xsize)/2];
	    out[2] = ptr[(x+5*state->xsize)/2];
	    out += 4;
	}

	state->shuffle((UINT8*) im->image[state->y],
		       state->buffer, state->xsize);

	if (++state->y >= state->ysize)
	    return -1; /* This can hardly happen */

	/* Unpack second line */
	out = state->buffer;
	for (x = 0; x < state->xsize; x++) {
	    out[0] = ptr[x+state->xsize];
	    out[1] = ptr[(x+4*state->xsize)/2];
	    out[2] = ptr[(x+5*state->xsize)/2];
	    out += 4;
	}

	state->shuffle((UINT8*) im->image[state->y],
		       state->buffer, state->xsize);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -47,7 +47,7 @@
 	    out[0] = ptr[x];
 	    out[1] = ptr[(x+4*state->xsize)/2];
 	    out[2] = ptr[(x+5*state->xsize)/2];
-	    out += 4;
+	    out += 3;
 	}
 
 	state->shuffle((UINT8*) im->image[state->y],
@@ -62,7 +62,7 @@
 	    out[0] = ptr[x+state->xsize];
 	    out[1] = ptr[(x+4*state->xsize)/2];
 	    out[2] = ptr[(x+5*state->xsize)/2];
-	    out += 4;
+	    out += 3;
 	}
 
 	state->shuffle((UINT8*) im->image[state->y],
```
