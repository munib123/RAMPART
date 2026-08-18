# CrossVul Fix Pair: Reachable Assertion in c
**Pair ID:** 219_1
**Vulnerability Class:** Reachable Assertion
**CWE:** CWE-617
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `219_1`)

## Vulnerability Information & PoC

## Description
Reachable Assertion - While assertion is good for catching logic errors and reducing the chances of reaching more serious vulnerability conditions, it can still lead to a denial of service.

## Vulnerable Code
```c
Lines 30-70 of the vulnerable file.

#include "libavutil/cpu.h"
#include "avcodec.h"
#include "error_resilience.h"
#include "flv.h"
#include "h263.h"
#include "h263_parser.h"
#include "hwaccel.h"
#include "internal.h"
#include "mpeg_er.h"
#include "mpeg4video.h"
#include "mpeg4video_parser.h"
#include "mpegutils.h"
#include "mpegvideo.h"
#include "msmpeg4.h"
#include "qpeldsp.h"
#include "thread.h"
#include "wmv2.h"

static enum AVPixelFormat h263_get_format(AVCodecContext *avctx)
{
    /* MPEG-4 Studio Profile only, not supported by hardware */
    if (avctx->bits_per_raw_sample > 8) {
        av_assert1(avctx->profile == FF_PROFILE_MPEG4_SIMPLE_STUDIO);
        return avctx->pix_fmt;
    }

    if (avctx->codec->id == AV_CODEC_ID_MSS2)
        return AV_PIX_FMT_YUV420P;

    if (CONFIG_GRAY && (avctx->flags & AV_CODEC_FLAG_GRAY)) {
        if (avctx->color_range == AVCOL_RANGE_UNSPECIFIED)
            avctx->color_range = AVCOL_RANGE_MPEG;
        return AV_PIX_FMT_GRAY8;
    }

    return avctx->pix_fmt = ff_get_format(avctx, avctx->codec->pix_fmts);
}

av_cold int ff_h263_decode_init(AVCodecContext *avctx)
{
    MpegEncContext *s = avctx->priv_data;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -47,9 +47,10 @@
 
 static enum AVPixelFormat h263_get_format(AVCodecContext *avctx)
 {
+    MpegEncContext *s = avctx->priv_data;
     /* MPEG-4 Studio Profile only, not supported by hardware */
     if (avctx->bits_per_raw_sample > 8) {
-        av_assert1(avctx->profile == FF_PROFILE_MPEG4_SIMPLE_STUDIO);
+        av_assert1(s->studio_profile);
         return avctx->pix_fmt;
     }
 
@@ -670,7 +671,8 @@
 
     av_assert1(s->bitstream_buffer_size == 0);
 frame_end:
-    ff_er_frame_end(&s->er);
+    if (!s->studio_profile)
+        ff_er_frame_end(&s->er);
 
     if (avctx->hwaccel) {
         ret = avctx->hwaccel->end_frame(avctx);
```
