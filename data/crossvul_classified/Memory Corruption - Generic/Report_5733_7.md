# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5733_7
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5733_7`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 287-327 of the vulnerable file.

        for (i = 0; i < in->height; i ++) {
            int w = inlink->w;
            const uint8_t (*tab)[256] = (const uint8_t (*)[256])s->lut;
            inrow  = inrow0;
            outrow = outrow0;
            for (j = 0; j < w; j++) {
                switch (s->step) {
                case 4:  outrow[3] = tab[3][inrow[3]]; // Fall-through
                case 3:  outrow[2] = tab[2][inrow[2]]; // Fall-through
                case 2:  outrow[1] = tab[1][inrow[1]]; // Fall-through
                default: outrow[0] = tab[0][inrow[0]];
                }
                outrow += s->step;
                inrow  += s->step;
            }
            inrow0  += in ->linesize[0];
            outrow0 += out->linesize[0];
        }
    } else {
        /* planar */
        for (plane = 0; plane < 4 && in->data[plane]; plane++) {
            int vsub = plane == 1 || plane == 2 ? s->vsub : 0;
            int hsub = plane == 1 || plane == 2 ? s->hsub : 0;
            int h = FF_CEIL_RSHIFT(inlink->h, vsub);
            int w = FF_CEIL_RSHIFT(inlink->w, hsub);

            inrow  = in ->data[plane];
            outrow = out->data[plane];

            for (i = 0; i < h; i++) {
                const uint8_t *tab = s->lut[plane];
                for (j = 0; j < w; j++)
                    outrow[j] = tab[inrow[j]];
                inrow  += in ->linesize[plane];
                outrow += out->linesize[plane];
            }
        }
    }

    if (!direct)
        av_frame_free(&in);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -304,7 +304,7 @@
         }
     } else {
         /* planar */
-        for (plane = 0; plane < 4 && in->data[plane]; plane++) {
+        for (plane = 0; plane < 4 && in->data[plane] && in->linesize[plane]; plane++) {
             int vsub = plane == 1 || plane == 2 ? s->vsub : 0;
             int hsub = plane == 1 || plane == 2 ? s->hsub : 0;
             int h = FF_CEIL_RSHIFT(inlink->h, vsub);
```
