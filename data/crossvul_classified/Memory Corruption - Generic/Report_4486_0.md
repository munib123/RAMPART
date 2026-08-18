# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 4486_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4486_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 1825-1869 of the vulnerable file.


    // save pointer we are going to use in decode_block
    s->buf      = avpkt->data;
    s->buf_size = avpkt->size;

    // Zero out the start if ymin is not 0
    for (i = 0; i < planes; i++) {
        ptr = picture->data[i];
        for (y = 0; y < FFMIN(s->ymin, s->h); y++) {
            memset(ptr, 0, out_line_size);
            ptr += picture->linesize[i];
        }
    }

    s->picture = picture;

    avctx->execute2(avctx, decode_block, s->thread_data, NULL, nb_blocks);

    ymax = FFMAX(0, s->ymax + 1);
    // Zero out the end if ymax+1 is not h
    for (i = 0; i < planes; i++) {
        ptr = picture->data[i] + (ymax * picture->linesize[i]);
        for (y = ymax; y < avctx->height; y++) {
            memset(ptr, 0, out_line_size);
            ptr += picture->linesize[i];
        }
    }

    picture->pict_type = AV_PICTURE_TYPE_I;
    *got_frame = 1;

    return avpkt->size;
}

static av_cold int decode_init(AVCodecContext *avctx)
{
    EXRContext *s = avctx->priv_data;
    uint32_t i;
    union av_intfloat32 t;
    float one_gamma = 1.0f / s->gamma;
    avpriv_trc_function trc_func = NULL;

    s->avctx              = avctx;

    ff_exrdsp_init(&s->dsp);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1842,13 +1842,14 @@
 
     ymax = FFMAX(0, s->ymax + 1);
     // Zero out the end if ymax+1 is not h
-    for (i = 0; i < planes; i++) {
-        ptr = picture->data[i] + (ymax * picture->linesize[i]);
-        for (y = ymax; y < avctx->height; y++) {
-            memset(ptr, 0, out_line_size);
-            ptr += picture->linesize[i];
-        }
-    }
+    if (ymax < avctx->height)
+        for (i = 0; i < planes; i++) {
+            ptr = picture->data[i] + (ymax * picture->linesize[i]);
+            for (y = ymax; y < avctx->height; y++) {
+                memset(ptr, 0, out_line_size);
+                ptr += picture->linesize[i];
+            }
+        }
 
     picture->pict_type = AV_PICTURE_TYPE_I;
     *got_frame = 1;
```
