# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5733_5
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5733_5`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 73-113 of the vulnerable file.

static int filter_frame(AVFilterLink *inlink, AVFrame *in)
{
    AVFilterContext *ctx  = inlink->dst;
    FlipContext *s     = ctx->priv;
    AVFilterLink *outlink = ctx->outputs[0];
    AVFrame *out;
    uint8_t *inrow, *outrow;
    int i, j, plane, step;

    out = ff_get_video_buffer(outlink, outlink->w, outlink->h);
    if (!out) {
        av_frame_free(&in);
        return AVERROR(ENOMEM);
    }
    av_frame_copy_props(out, in);

    /* copy palette if required */
    if (av_pix_fmt_desc_get(inlink->format)->flags & AV_PIX_FMT_FLAG_PAL)
        memcpy(out->data[1], in->data[1], AVPALETTE_SIZE);

    for (plane = 0; plane < 4 && in->data[plane]; plane++) {
        const int width  = (plane == 1 || plane == 2) ? FF_CEIL_RSHIFT(inlink->w, s->hsub) : inlink->w;
        const int height = (plane == 1 || plane == 2) ? FF_CEIL_RSHIFT(inlink->h, s->vsub) : inlink->h;
        step = s->max_step[plane];

        outrow = out->data[plane];
        inrow  = in ->data[plane] + (width - 1) * step;
        for (i = 0; i < height; i++) {
            switch (step) {
            case 1:
                for (j = 0; j < width; j++)
                    outrow[j] = inrow[-j];
            break;

            case 2:
            {
                uint16_t *outrow16 = (uint16_t *)outrow;
                uint16_t * inrow16 = (uint16_t *) inrow;
                for (j = 0; j < width; j++)
                    outrow16[j] = inrow16[-j];
            }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -90,7 +90,7 @@
     if (av_pix_fmt_desc_get(inlink->format)->flags & AV_PIX_FMT_FLAG_PAL)
         memcpy(out->data[1], in->data[1], AVPALETTE_SIZE);
 
-    for (plane = 0; plane < 4 && in->data[plane]; plane++) {
+    for (plane = 0; plane < 4 && in->data[plane] && in->linesize[plane]; plane++) {
         const int width  = (plane == 1 || plane == 2) ? FF_CEIL_RSHIFT(inlink->w, s->hsub) : inlink->w;
         const int height = (plane == 1 || plane == 2) ? FF_CEIL_RSHIFT(inlink->h, s->vsub) : inlink->h;
         step = s->max_step[plane];
```
