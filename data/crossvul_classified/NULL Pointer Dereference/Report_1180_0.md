# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 1180_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1180_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 1007-1047 of the vulnerable file.

        }

#if FF_API_AVCTX_TIMEBASE
        if (avctx->framerate.num > 0 && avctx->framerate.den > 0)
            avctx->time_base = av_inv_q(av_mul_q(avctx->framerate, (AVRational){avctx->ticks_per_frame, 1}));
#endif
    }
    if (codec->priv_data_size > 0 && avctx->priv_data && codec->priv_class) {
        av_assert0(*(const AVClass **)avctx->priv_data == codec->priv_class);
    }

end:
    ff_unlock_avcodec(codec);
    if (options) {
        av_dict_free(options);
        *options = tmp;
    }

    return ret;
free_and_end:
    if (avctx->codec &&
        (codec_init_ok ||
         (avctx->codec->caps_internal & FF_CODEC_CAP_INIT_CLEANUP)))
        avctx->codec->close(avctx);

    if (codec->priv_class && codec->priv_data_size)
        av_opt_free(avctx->priv_data);
    av_opt_free(avctx);

#if FF_API_CODED_FRAME
FF_DISABLE_DEPRECATION_WARNINGS
    av_frame_free(&avctx->coded_frame);
FF_ENABLE_DEPRECATION_WARNINGS
#endif

    av_dict_free(&tmp);
    av_freep(&avctx->priv_data);
    if (avctx->internal) {
        av_frame_free(&avctx->internal->to_free);
        av_frame_free(&avctx->internal->compat_decode_frame);
        av_frame_free(&avctx->internal->buffer_frame);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1024,7 +1024,7 @@
 
     return ret;
 free_and_end:
-    if (avctx->codec &&
+    if (avctx->codec && avctx->codec->close &&
         (codec_init_ok ||
          (avctx->codec->caps_internal & FF_CODEC_CAP_INIT_CLEANUP)))
         avctx->codec->close(avctx);
```
