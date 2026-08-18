# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5734_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5734_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 372-412 of the vulnerable file.


    if (sub_type != 2) {
        memcpy(transp, src, 3);
        src += 3;
    }
    npal = *src++ + 1;
    memcpy(pal, src, npal * 3); src += npal * 3;
    if (sub_type != 2) {
        for (i = 0; i < npal; i++) {
            if (!memcmp(pal + i * 3, transp, 3)) {
               tidx = i;
               break;
            }
        }
    }

    if (src_end - src < 2)
        return 0;
    zsize = (src[0] << 8) | src[1]; src += 2;

    if (src_end - src < zsize)
        return AVERROR_INVALIDDATA;

    ret = uncompress(c->kempf_buf, &dlen, src, zsize);
    if (ret)
        return AVERROR_INVALIDDATA;
    src += zsize;

    if (sub_type == 2) {
        kempf_restore_buf(c->kempf_buf, dlen, dst, c->framebuf_stride,
                          NULL, 0, width, height, pal, npal, tidx);
        return 0;
    }

    nblocks = *src++ + 1;
    cblocks = 0;
    bstride = FFALIGN(width, 16) >> 4;
    // blocks are coded LSB and we need normal bitreader for JPEG data
    bits = 0;
    for (i = 0; i < (FFALIGN(height, 16) >> 4); i++) {
        for (j = 0; j < (FFALIGN(width, 16) >> 4); j++) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -389,7 +389,7 @@
         return 0;
     zsize = (src[0] << 8) | src[1]; src += 2;
 
-    if (src_end - src < zsize)
+    if (src_end - src < zsize + (sub_type != 2))
         return AVERROR_INVALIDDATA;
 
     ret = uncompress(c->kempf_buf, &dlen, src, zsize);
@@ -411,6 +411,8 @@
     for (i = 0; i < (FFALIGN(height, 16) >> 4); i++) {
         for (j = 0; j < (FFALIGN(width, 16) >> 4); j++) {
             if (!bits) {
+                if (src >= src_end)
+                    return AVERROR_INVALIDDATA;
                 bitbuf = *src++;
                 bits   = 8;
             }
```
