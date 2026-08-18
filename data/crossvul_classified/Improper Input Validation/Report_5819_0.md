# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5819_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5819_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 370-410 of the vulnerable file.

                skip_bits(&gb, 3);
                s->color_depth    = get_bits(&gb, 2);
                has_diff          = get_bits1(&gb);
                s->zlibprime_curr = get_bits1(&gb);
                s->zlibprime_prev = get_bits1(&gb);

                if (s->color_depth != 0 && s->color_depth != 2) {
                    av_log(avctx, AV_LOG_ERROR,
                           "%dx%d invalid color depth %d\n", i, j, s->color_depth);
                    return AVERROR_INVALIDDATA;
                }

                if (has_diff) {
                    if (!s->keyframe) {
                        av_log(avctx, AV_LOG_ERROR,
                               "inter frame without keyframe\n");
                        return AVERROR_INVALIDDATA;
                    }
                    s->diff_start  = get_bits(&gb, 8);
                    s->diff_height = get_bits(&gb, 8);
                    av_log(avctx, AV_LOG_DEBUG,
                           "%dx%d diff start %d height %d\n",
                           i, j, s->diff_start, s->diff_height);
                    size -= 2;
                }

                if (s->zlibprime_prev)
                    av_log(avctx, AV_LOG_DEBUG, "%dx%d zlibprime_prev\n", i, j);

                if (s->zlibprime_curr) {
                    int col = get_bits(&gb, 8);
                    int row = get_bits(&gb, 8);
                    av_log(avctx, AV_LOG_DEBUG, "%dx%d zlibprime_curr %dx%d\n", i, j, col, row);
                    size -= 2;
                    avpriv_request_sample(avctx, "zlibprime_curr");
                    return AVERROR_PATCHWELCOME;
                }
                if (!s->blocks && (s->zlibprime_curr || s->zlibprime_prev)) {
                    av_log(avctx, AV_LOG_ERROR, "no data available for zlib "
                           "priming\n");
                    return AVERROR_INVALIDDATA;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -387,6 +387,10 @@
                     }
                     s->diff_start  = get_bits(&gb, 8);
                     s->diff_height = get_bits(&gb, 8);
+                    if (s->diff_start + s->diff_height > cur_blk_height) {
+                        av_log(avctx, AV_LOG_ERROR, "Block parameters invalid\n");
+                        return AVERROR_INVALIDDATA;
+                    }
                     av_log(avctx, AV_LOG_DEBUG,
                            "%dx%d diff start %d height %d\n",
                            i, j, s->diff_start, s->diff_height);
```
