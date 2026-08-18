# CrossVul Fix Pair: Reachable Assertion in c
**Pair ID:** 219_0
**Vulnerability Class:** Reachable Assertion
**CWE:** CWE-617
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `219_0`)

## Vulnerability Information & PoC

## Description
Reachable Assertion - While assertion is good for catching logic errors and reducing the chances of reaching more serious vulnerability conditions, it can still lead to a denial of service.

## Vulnerable Code
```c
Lines 797-838 of the vulnerable file.

void ff_er_frame_start(ERContext *s)
{
    if (!s->avctx->error_concealment)
        return;

    if (!s->mecc_inited) {
        ff_me_cmp_init(&s->mecc, s->avctx);
        s->mecc_inited = 1;
    }

    memset(s->error_status_table, ER_MB_ERROR | VP_START | ER_MB_END,
           s->mb_stride * s->mb_height * sizeof(uint8_t));
    atomic_init(&s->error_count, 3 * s->mb_num);
    s->error_occurred = 0;
}

static int er_supported(ERContext *s)
{
    if(s->avctx->hwaccel && s->avctx->hwaccel->decode_slice           ||
       !s->cur_pic.f                                                  ||
       s->cur_pic.field_picture                                       ||
       s->avctx->profile == FF_PROFILE_MPEG4_SIMPLE_STUDIO
    )
        return 0;
    return 1;
}

/**
 * Add a slice.
 * @param endx   x component of the last macroblock, can be -1
 *               for the last of the previous line
 * @param status the status at the end (ER_MV_END, ER_AC_ERROR, ...), it is
 *               assumed that no earlier end or error of the same type occurred
 */
void ff_er_add_slice(ERContext *s, int startx, int starty,
                     int endx, int endy, int status)
{
    const int start_i  = av_clip(startx + starty * s->mb_width, 0, s->mb_num - 1);
    const int end_i    = av_clip(endx   + endy   * s->mb_width, 0, s->mb_num);
    const int start_xy = s->mb_index2xy[start_i];
    const int end_xy   = s->mb_index2xy[end_i];
    int mask           = -1;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -814,8 +814,7 @@
 {
     if(s->avctx->hwaccel && s->avctx->hwaccel->decode_slice           ||
        !s->cur_pic.f                                                  ||
-       s->cur_pic.field_picture                                       ||
-       s->avctx->profile == FF_PROFILE_MPEG4_SIMPLE_STUDIO
+       s->cur_pic.field_picture
     )
         return 0;
     return 1;
```
