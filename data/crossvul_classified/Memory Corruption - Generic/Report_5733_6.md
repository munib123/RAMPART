# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5733_6
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5733_6`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 133-173 of the vulnerable file.

    int src_linesize, psrc_linesize, dst_linesize, bwidth;
    int x, y, plane, val, hi, lo, g, h, n = kerndeint->frame++;
    double valf;

    const int thresh = kerndeint->thresh;
    const int order  = kerndeint->order;
    const int map    = kerndeint->map;
    const int sharp  = kerndeint->sharp;
    const int twoway = kerndeint->twoway;

    const int is_packed_rgb = kerndeint->is_packed_rgb;

    outpic = ff_get_video_buffer(outlink, outlink->w, outlink->h);
    if (!outpic) {
        av_frame_free(&inpic);
        return AVERROR(ENOMEM);
    }
    av_frame_copy_props(outpic, inpic);
    outpic->interlaced_frame = 0;

    for (plane = 0; inpic->data[plane] && plane < 4; plane++) {
        h = plane == 0 ? inlink->h : FF_CEIL_RSHIFT(inlink->h, kerndeint->vsub);
        bwidth = kerndeint->tmp_bwidth[plane];

        srcp = srcp_saved = inpic->data[plane];
        src_linesize      = inpic->linesize[plane];
        psrc_linesize     = kerndeint->tmp_linesize[plane];
        dstp = dstp_saved = outpic->data[plane];
        dst_linesize      = outpic->linesize[plane];
        srcp              = srcp_saved + (1 - order) * src_linesize;
        dstp              = dstp_saved + (1 - order) * dst_linesize;

        for (y = 0; y < h; y += 2) {
            memcpy(dstp, srcp, bwidth);
            srcp += 2 * src_linesize;
            dstp += 2 * dst_linesize;
        }

        // Copy through the lines that will be missed below.
        memcpy(dstp_saved + order            * dst_linesize, srcp_saved + (1 -     order) * src_linesize, bwidth);
        memcpy(dstp_saved + (2 + order    )  * dst_linesize, srcp_saved + (3 -     order) * src_linesize, bwidth);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -150,7 +150,7 @@
     av_frame_copy_props(outpic, inpic);
     outpic->interlaced_frame = 0;
 
-    for (plane = 0; inpic->data[plane] && plane < 4; plane++) {
+    for (plane = 0; plane < 4 && inpic->data[plane] && inpic->linesize[plane]; plane++) {
         h = plane == 0 ? inlink->h : FF_CEIL_RSHIFT(inlink->h, kerndeint->vsub);
         bwidth = kerndeint->tmp_bwidth[plane];
 
```
