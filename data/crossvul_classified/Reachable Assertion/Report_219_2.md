# CrossVul Fix Pair: Reachable Assertion in c
**Pair ID:** 219_2
**Vulnerability Class:** Reachable Assertion
**CWE:** CWE-617
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `219_2`)

## Vulnerability Information & PoC

## Description
Reachable Assertion - While assertion is good for catching logic errors and reducing the chances of reaching more serious vulnerability conditions, it can still lead to a denial of service.

## Vulnerable Code
```c
Lines 3227-3267 of the vulnerable file.

        } else if (startcode == VISUAL_OBJ_STARTCODE) {
            if (s->studio_profile) {
                if ((ret = decode_studiovisualobject(ctx, gb)) < 0)
                    return ret;
            } else
                mpeg4_decode_visual_object(s, gb);
        } else if (startcode == VOP_STARTCODE) {
            break;
        }

        align_get_bits(gb);
        startcode = 0xff;
    }

end:
    if (s->avctx->flags & AV_CODEC_FLAG_LOW_DELAY)
        s->low_delay = 1;
    s->avctx->has_b_frames = !s->low_delay;

    if (s->studio_profile) {
        av_assert0(s->avctx->profile == FF_PROFILE_MPEG4_SIMPLE_STUDIO);
        if (!s->avctx->bits_per_raw_sample) {
            av_log(s->avctx, AV_LOG_ERROR, "Missing VOL header\n");
            return AVERROR_INVALIDDATA;
        }
        return decode_studio_vop_header(ctx, gb);
    } else
        return decode_vop_header(ctx, gb);
}

av_cold void ff_mpeg4videodec_static_init(void) {
    static int done = 0;

    if (!done) {
        ff_rl_init(&ff_mpeg4_rl_intra, ff_mpeg4_static_rl_table_store[0]);
        ff_rl_init(&ff_rvlc_rl_inter, ff_mpeg4_static_rl_table_store[1]);
        ff_rl_init(&ff_rvlc_rl_intra, ff_mpeg4_static_rl_table_store[2]);
        INIT_VLC_RL(ff_mpeg4_rl_intra, 554);
        INIT_VLC_RL(ff_rvlc_rl_inter, 1072);
        INIT_VLC_RL(ff_rvlc_rl_intra, 1072);
        INIT_VLC_STATIC(&dc_lum, DC_VLC_BITS, 10 /* 13 */,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3244,7 +3244,6 @@
     s->avctx->has_b_frames = !s->low_delay;
 
     if (s->studio_profile) {
-        av_assert0(s->avctx->profile == FF_PROFILE_MPEG4_SIMPLE_STUDIO);
         if (!s->avctx->bits_per_raw_sample) {
             av_log(s->avctx, AV_LOG_ERROR, "Missing VOL header\n");
             return AVERROR_INVALIDDATA;
```
