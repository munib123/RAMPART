# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 191_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `191_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 3092-3132 of the vulnerable file.


    return 0;
}

/**
 * Decode MPEG-4 headers.
 * @return <0 if no VOP found (or a damaged one)
 *         FRAME_SKIPPED if a not coded VOP is found
 *         0 if a VOP is found
 */
int ff_mpeg4_decode_picture_header(Mpeg4DecContext *ctx, GetBitContext *gb)
{
    MpegEncContext *s = &ctx->m;
    unsigned startcode, v;
    int ret;
    int vol = 0;

    /* search next start code */
    align_get_bits(gb);

    if (s->codec_tag == AV_RL32("WV1F") && show_bits(gb, 24) == 0x575630) {
        skip_bits(gb, 24);
        if (get_bits(gb, 8) == 0xF0)
            goto end;
    }

    startcode = 0xff;
    for (;;) {
        if (get_bits_count(gb) >= gb->size_in_bits) {
            if (gb->size_in_bits == 8 &&
                (ctx->divx_version >= 0 || ctx->xvid_build >= 0) || s->codec_tag == AV_RL32("QMP4")) {
                av_log(s->avctx, AV_LOG_VERBOSE, "frame skip %d\n", gb->size_in_bits);
                return FRAME_SKIPPED;  // divx bug
            } else
                return AVERROR_INVALIDDATA;  // end of stream
        }

        /* use the bits after the test */
        v = get_bits(gb, 8);
        startcode = ((startcode << 8) | v) & 0xffffffff;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3108,6 +3108,12 @@
 
     /* search next start code */
     align_get_bits(gb);
+
+    // If we have not switched to studio profile than we also did not switch bps
+    // that means something else (like a previous instance) outside set bps which
+    // would be inconsistant with the currect state, thus reset it
+    if (!s->studio_profile && s->avctx->bits_per_raw_sample != 8)
+        s->avctx->bits_per_raw_sample = 0;
 
     if (s->codec_tag == AV_RL32("WV1F") && show_bits(gb, 24) == 0x575630) {
         skip_bits(gb, 24);
```
