# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 3420_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3420_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 314-354 of the vulnerable file.

        ret = decode_unit(s, &s->pixel_model[1][cx + cx1], 400, &g);
        if (ret < 0)
            return ret;

        cx1 = (cx << 6) & 0xFC0;
        cx = g >> cxshift;
        ret = decode_unit(s, &s->pixel_model[2][cx + cx1], 400, &b);
        if (ret < 0)
            return ret;

        cx1 = (cx << 6) & 0xFC0;
        cx = b >> cxshift;

        ret = decode_value(s, s->run_model[0], 256, 400, &run);
        if (ret < 0)
            return ret;

        clr = (b << 16) + (g << 8) + r;
        k += run;
        while (run-- > 0) {
            dst[y * linesize + x] = clr;
            lx = x;
            ly = y;
            x++;
            if (x >= avctx->width) {
                x = 0;
                y++;
            }
        }
    }
    off = -linesize - 1;
    ptype = 0;

    while (x < avctx->width && y < avctx->height) {
        ret = decode_value(s, s->op_model[ptype], 6, 1000, &ptype);
        if (ret < 0)
            return ret;
        if (ptype == 0) {
            ret = decode_unit(s, &s->pixel_model[0][cx + cx1], 400, &r);
            if (ret < 0)
                return ret;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -331,6 +331,9 @@
         clr = (b << 16) + (g << 8) + r;
         k += run;
         while (run-- > 0) {
+            if (y >= avctx->height)
+                return AVERROR_INVALIDDATA;
+
             dst[y * linesize + x] = clr;
             lx = x;
             ly = y;
```
