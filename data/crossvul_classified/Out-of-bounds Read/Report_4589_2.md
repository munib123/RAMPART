# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 4589_2
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4589_2`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 23-64 of the vulnerable file.


#define	I32(ptr)\
    ((ptr)[0] + ((ptr)[1] << 8) + ((ptr)[2] << 16) + ((ptr)[3] << 24))


int
ImagingFliDecode(Imaging im, ImagingCodecState state, UINT8* buf, Py_ssize_t bytes)
{
    UINT8* ptr;
    int framesize;
    int c, chunks, advance;
    int l, lines;
    int i, j, x = 0, y, ymax;

    /* If not even the chunk size is present, we'd better leave */

    if (bytes < 4)
	return 0;

    /* We don't decode anything unless we have a full chunk in the
       input buffer (on the other hand, the Python part of the driver
       makes sure this is always the case) */

    ptr = buf;

    framesize = I32(ptr);
    if (framesize < I32(ptr))
	return 0;

    /* Make sure this is a frame chunk.  The Python driver takes
       case of other chunk types. */

    if (I16(ptr+4) != 0xF1FA) {
	state->errcode = IMAGING_CODEC_UNKNOWN;
	return -1;
    }

    chunks = I16(ptr+6);
    ptr += 16;
    bytes -= 16;

    /* Process subchunks */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -40,8 +40,7 @@
 	return 0;
 
     /* We don't decode anything unless we have a full chunk in the
-       input buffer (on the other hand, the Python part of the driver
-       makes sure this is always the case) */
+       input buffer */
 
     ptr = buf;
 
@@ -52,6 +51,10 @@
     /* Make sure this is a frame chunk.  The Python driver takes
        case of other chunk types. */
 
+    if (bytes < 8) {
+        state->errcode = IMAGING_CODEC_OVERRUN;
+        return -1;
+    }
     if (I16(ptr+4) != 0xF1FA) {
 	state->errcode = IMAGING_CODEC_UNKNOWN;
 	return -1;
```
