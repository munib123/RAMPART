# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 3418_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3418_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1317-1358 of the vulnerable file.

    }

    /* apply alpha filtering */
    if (s->alpha_filter)
        alpha_inverse_prediction(p, s->alpha_filter);

    return 0;
}

static int vp8_lossy_decode_frame(AVCodecContext *avctx, AVFrame *p,
                                  int *got_frame, uint8_t *data_start,
                                  unsigned int data_size)
{
    WebPContext *s = avctx->priv_data;
    AVPacket pkt;
    int ret;

    if (!s->initialized) {
        ff_vp8_decode_init(avctx);
        s->initialized = 1;
        if (s->has_alpha)
            avctx->pix_fmt = AV_PIX_FMT_YUVA420P;
    }
    s->lossless = 0;

    if (data_size > INT_MAX) {
        av_log(avctx, AV_LOG_ERROR, "unsupported chunk size\n");
        return AVERROR_PATCHWELCOME;
    }

    av_init_packet(&pkt);
    pkt.data = data_start;
    pkt.size = data_size;

    ret = ff_vp8_decode_frame(avctx, p, got_frame, &pkt);
    if (ret < 0)
        return ret;

    update_canvas_size(avctx, avctx->width, avctx->height);

    if (s->has_alpha) {
        ret = vp8_lossy_decode_alpha(avctx, p, s->alpha_data,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1334,9 +1334,8 @@
     if (!s->initialized) {
         ff_vp8_decode_init(avctx);
         s->initialized = 1;
-        if (s->has_alpha)
-            avctx->pix_fmt = AV_PIX_FMT_YUVA420P;
-    }
+    }
+    avctx->pix_fmt = s->has_alpha ? AV_PIX_FMT_YUVA420P : AV_PIX_FMT_YUV420P;
     s->lossless = 0;
 
     if (data_size > INT_MAX) {
```
