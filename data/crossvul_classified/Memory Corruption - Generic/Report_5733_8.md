# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5733_8
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5733_8`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 197-237 of the vulnerable file.

    outlink->w = s->w;
    outlink->h = s->h;
    return 0;
}

static AVFrame *get_video_buffer(AVFilterLink *inlink, int w, int h)
{
    PadContext *s = inlink->dst->priv;

    AVFrame *frame = ff_get_video_buffer(inlink->dst->outputs[0],
                                         w + (s->w - s->in_w),
                                         h + (s->h - s->in_h));
    int plane;

    if (!frame)
        return NULL;

    frame->width  = w;
    frame->height = h;

    for (plane = 0; plane < 4 && frame->data[plane]; plane++) {
        int hsub = s->draw.hsub[plane];
        int vsub = s->draw.vsub[plane];
        frame->data[plane] += (s->x >> hsub) * s->draw.pixelstep[plane] +
                              (s->y >> vsub) * frame->linesize[plane];
    }

    return frame;
}

/* check whether each plane in this buffer can be padded without copying */
static int buffer_needs_copy(PadContext *s, AVFrame *frame, AVBufferRef *buf)
{
    int planes[4] = { -1, -1, -1, -1}, *p = planes;
    int i, j;

    /* get all planes in this buffer */
    for (i = 0; i < FF_ARRAY_ELEMS(planes) && frame->data[i]; i++) {
        if (av_frame_get_plane_buffer(frame, i) == buf)
            *p++ = i;
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -214,7 +214,7 @@
     frame->width  = w;
     frame->height = h;
 
-    for (plane = 0; plane < 4 && frame->data[plane]; plane++) {
+    for (plane = 0; plane < 4 && frame->data[plane] && frame->linesize[plane]; plane++) {
         int hsub = s->draw.hsub[plane];
         int vsub = s->draw.vsub[plane];
         frame->data[plane] += (s->x >> hsub) * s->draw.pixelstep[plane] +
@@ -311,7 +311,7 @@
         int i;
 
         out = in;
-        for (i = 0; i < 4 && out->data[i]; i++) {
+        for (i = 0; i < 4 && out->data[i] && out->linesize[i]; i++) {
             int hsub = s->draw.hsub[i];
             int vsub = s->draw.vsub[i];
             out->data[i] -= (s->x >> hsub) * s->draw.pixelstep[i] +
```
