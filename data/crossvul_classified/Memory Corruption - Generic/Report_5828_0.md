# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5828_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5828_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1261-1301 of the vulnerable file.

            s->cdef[s->ncomponents-1] = 0;
    }

    if (s->precision <= 8) {
        for (compno = 0; compno < s->ncomponents; compno++) {
            Jpeg2000Component *comp = tile->comp + compno;
            Jpeg2000CodingStyle *codsty = tile->codsty + compno;
            float *datap = comp->f_data;
            int32_t *i_datap = comp->i_data;
            int cbps = s->cbps[compno];
            int w = tile->comp[compno].coord[0][1] - s->image_offset_x;
            int planar = !!picture->data[2];
            int pixelsize = planar ? 1 : s->ncomponents;
            int plane = 0;

            if (planar)
                plane = s->cdef[compno] ? s->cdef[compno]-1 : (s->ncomponents-1);


            y    = tile->comp[compno].coord[1][0] - s->image_offset_y;
            line = picture->data[plane] + y * picture->linesize[plane];
            for (; y < tile->comp[compno].coord[1][1] - s->image_offset_y; y += s->cdy[compno]) {
                uint8_t *dst;

                x   = tile->comp[compno].coord[0][0] - s->image_offset_x;
                dst = line + x * pixelsize + compno*!planar;

                if (codsty->transform == FF_DWT97) {
                    for (; x < w; x += s->cdx[compno]) {
                        int val = lrintf(*datap) + (1 << (cbps - 1));
                        /* DC level shift and clip see ISO 15444-1:2002 G.1.2 */
                        val = av_clip(val, 0, (1 << cbps) - 1);
                        *dst = val << (8 - cbps);
                        datap++;
                        dst += pixelsize;
                    }
                } else {
                    for (; x < w; x += s->cdx[compno]) {
                        int val = *i_datap + (1 << (cbps - 1));
                        /* DC level shift and clip see ISO 15444-1:2002 G.1.2 */
                        val = av_clip(val, 0, (1 << cbps) - 1);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1278,12 +1278,12 @@
 
 
             y    = tile->comp[compno].coord[1][0] - s->image_offset_y;
-            line = picture->data[plane] + y * picture->linesize[plane];
+            line = picture->data[plane] + y / s->cdy[compno] * picture->linesize[plane];
             for (; y < tile->comp[compno].coord[1][1] - s->image_offset_y; y += s->cdy[compno]) {
                 uint8_t *dst;
 
                 x   = tile->comp[compno].coord[0][0] - s->image_offset_x;
-                dst = line + x * pixelsize + compno*!planar;
+                dst = line + x / s->cdx[compno] * pixelsize + compno*!planar;
 
                 if (codsty->transform == FF_DWT97) {
                     for (; x < w; x += s->cdx[compno]) {
@@ -1324,12 +1324,12 @@
                 plane = s->cdef[compno] ? s->cdef[compno]-1 : (s->ncomponents-1);
 
             y     = tile->comp[compno].coord[1][0] - s->image_offset_y;
-            linel = (uint16_t *)picture->data[plane] + y * (picture->linesize[plane] >> 1);
+            linel = (uint16_t *)picture->data[plane] + y / s->cdy[compno] * (picture->linesize[plane] >> 1);
             for (; y < tile->comp[compno].coord[1][1] - s->image_offset_y; y += s->cdy[compno]) {
                 uint16_t *dst;
 
                 x   = tile->comp[compno].coord[0][0] - s->image_offset_x;
-                dst = linel + (x * pixelsize + compno*!planar);
+                dst = linel + (x / s->cdx[compno] * pixelsize + compno*!planar);
                 if (codsty->transform == FF_DWT97) {
                     for (; x < w; x += s-> cdx[compno]) {
                         int  val = lrintf(*datap) + (1 << (cbps - 1));
```
