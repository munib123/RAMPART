# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5733_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5733_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 296-336 of the vulnerable file.

}

static int filter_frame(AVFilterLink *inlink, AVFrame *in)
{
    AVFilterContext *ctx = inlink->dst;
    BoxBlurContext *s = ctx->priv;
    AVFilterLink *outlink = inlink->dst->outputs[0];
    AVFrame *out;
    int plane;
    int cw = FF_CEIL_RSHIFT(inlink->w, s->hsub), ch = FF_CEIL_RSHIFT(in->height, s->vsub);
    int w[4] = { inlink->w, cw, cw, inlink->w };
    int h[4] = { in->height, ch, ch, in->height };

    out = ff_get_video_buffer(outlink, outlink->w, outlink->h);
    if (!out) {
        av_frame_free(&in);
        return AVERROR(ENOMEM);
    }
    av_frame_copy_props(out, in);

    for (plane = 0; in->data[plane] && plane < 4; plane++)
        hblur(out->data[plane], out->linesize[plane],
              in ->data[plane], in ->linesize[plane],
              w[plane], h[plane], s->radius[plane], s->power[plane],
              s->temp);

    for (plane = 0; in->data[plane] && plane < 4; plane++)
        vblur(out->data[plane], out->linesize[plane],
              out->data[plane], out->linesize[plane],
              w[plane], h[plane], s->radius[plane], s->power[plane],
              s->temp);

    av_frame_free(&in);

    return ff_filter_frame(outlink, out);
}

#define OFFSET(x) offsetof(BoxBlurContext, x)
#define FLAGS AV_OPT_FLAG_VIDEO_PARAM|AV_OPT_FLAG_FILTERING_PARAM

static const AVOption boxblur_options[] = {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -313,13 +313,13 @@
     }
     av_frame_copy_props(out, in);
 
-    for (plane = 0; in->data[plane] && plane < 4; plane++)
+    for (plane = 0; plane < 4 && in->data[plane] && in->linesize[plane]; plane++)
         hblur(out->data[plane], out->linesize[plane],
               in ->data[plane], in ->linesize[plane],
               w[plane], h[plane], s->radius[plane], s->power[plane],
               s->temp);
 
-    for (plane = 0; in->data[plane] && plane < 4; plane++)
+    for (plane = 0; plane < 4 && in->data[plane] && in->linesize[plane]; plane++)
         vblur(out->data[plane], out->linesize[plane],
               out->data[plane], out->linesize[plane],
               w[plane], h[plane], s->radius[plane], s->power[plane],
```
