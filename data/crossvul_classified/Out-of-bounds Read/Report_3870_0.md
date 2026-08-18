# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 3870_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3870_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 5-48 of the vulnerable file.

 * decoder for PCX image data.
 *
 * history:
 *	95-09-14 fl	Created
 *
 * Copyright (c) Fredrik Lundh 1995.
 * Copyright (c) Secret Labs AB 1997.
 *
 * See the README file for information on usage and redistribution.
 */


#include "Imaging.h"

int
ImagingPcxDecode(Imaging im, ImagingCodecState state, UINT8* buf, Py_ssize_t bytes)
{
    UINT8 n;
    UINT8* ptr;

    if (strcmp(im->mode, "1") == 0 && state->xsize > state->bytes * 8) {
        state->errcode = IMAGING_CODEC_OVERRUN;
        return -1;
    } else if (strcmp(im->mode, "P") == 0 && state->xsize > state->bytes) {
        state->errcode = IMAGING_CODEC_OVERRUN;
        return -1;
    }

    ptr = buf;

    for (;;) {

	if (bytes < 1)
	    return ptr - buf;

	if ((*ptr & 0xC0) == 0xC0) {

	    /* Run */
	    if (bytes < 2)
		return ptr - buf;

	    n = ptr[0] & 0x3F;

	    while (n > 0) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -22,10 +22,7 @@
     UINT8 n;
     UINT8* ptr;
 
-    if (strcmp(im->mode, "1") == 0 && state->xsize > state->bytes * 8) {
-        state->errcode = IMAGING_CODEC_OVERRUN;
-        return -1;
-    } else if (strcmp(im->mode, "P") == 0 && state->xsize > state->bytes) {
+    if ((state->xsize * state->bits + 7) / 8 > state->bytes) {
         state->errcode = IMAGING_CODEC_OVERRUN;
         return -1;
     }
```
