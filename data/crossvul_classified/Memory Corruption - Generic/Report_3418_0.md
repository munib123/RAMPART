# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 3418_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3418_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 2533-2573 of the vulnerable file.

{
    return vp78_decode_mb_row_sliced(avctx, tdata, jobnr, threadnr, IS_VP7);
}

static int vp8_decode_mb_row_sliced(AVCodecContext *avctx, void *tdata,
                                    int jobnr, int threadnr)
{
    return vp78_decode_mb_row_sliced(avctx, tdata, jobnr, threadnr, IS_VP8);
}


static av_always_inline
int vp78_decode_frame(AVCodecContext *avctx, void *data, int *got_frame,
                      AVPacket *avpkt, int is_vp7)
{
    VP8Context *s = avctx->priv_data;
    int ret, i, referenced, num_jobs;
    enum AVDiscard skip_thresh;
    VP8Frame *av_uninit(curframe), *prev_frame;

    if (is_vp7)
        ret = vp7_decode_frame_header(s, avpkt->data, avpkt->size);
    else
        ret = vp8_decode_frame_header(s, avpkt->data, avpkt->size);

    if (ret < 0)
        goto err;

    prev_frame = s->framep[VP56_FRAME_CURRENT];

    referenced = s->update_last || s->update_golden == VP56_FRAME_CURRENT ||
                 s->update_altref == VP56_FRAME_CURRENT;

    skip_thresh = !referenced ? AVDISCARD_NONREF
                              : !s->keyframe ? AVDISCARD_NONKEY
                                             : AVDISCARD_ALL;

    if (avctx->skip_frame >= skip_thresh) {
        s->invisible = 1;
        memcpy(&s->next_framep[0], &s->framep[0], sizeof(s->framep[0]) * 4);
        goto skip_decode;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2550,6 +2550,8 @@
     enum AVDiscard skip_thresh;
     VP8Frame *av_uninit(curframe), *prev_frame;
 
+    av_assert0(avctx->pix_fmt == AV_PIX_FMT_YUVA420P || avctx->pix_fmt == AV_PIX_FMT_YUV420P);
+
     if (is_vp7)
         ret = vp7_decode_frame_header(s, avpkt->data, avpkt->size);
     else
```
