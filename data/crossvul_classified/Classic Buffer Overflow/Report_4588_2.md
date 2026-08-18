# CrossVul Fix Pair: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') in c
**Pair ID:** 4588_2
**Vulnerability Class:** Classic Buffer Overflow
**CWE:** CWE-120
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4588_2`)

## Vulnerability Information & PoC

## Description
Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') - A buffer overflow condition exists when a product attempts to put more data in a buffer than it can hold, or when it attempts to put data in a memory area outside of the boundaries of a buffer.

## Vulnerable Code
```c
Lines 6-46 of the vulnerable file.

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
		if (state->x >= state->bytes) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -23,6 +23,9 @@
     UINT8* ptr;
 
     if (strcmp(im->mode, "1") == 0 && state->xsize > state->bytes * 8) {
+        state->errcode = IMAGING_CODEC_OVERRUN;
+        return -1;
+    } else if (strcmp(im->mode, "P") == 0 && state->xsize > state->bytes) {
         state->errcode = IMAGING_CODEC_OVERRUN;
         return -1;
     }
```
