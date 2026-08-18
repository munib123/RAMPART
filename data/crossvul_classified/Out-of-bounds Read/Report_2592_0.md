# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2592_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2592_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 281-322 of the vulnerable file.

    if (buf_size < ctx->cid_table->coding_unit_size) {
        av_log(ctx->avctx, AV_LOG_ERROR, "incorrect frame size (%d < %u).\n",
               buf_size, ctx->cid_table->coding_unit_size);
        return AVERROR_INVALIDDATA;
    }

    ctx->mb_width  = (ctx->width + 15)>> 4;
    ctx->mb_height = AV_RB16(buf + 0x16c);

    if ((ctx->height + 15) >> 4 == ctx->mb_height && frame->interlaced_frame)
        ctx->height <<= 1;

    av_log(ctx->avctx, AV_LOG_VERBOSE, "%dx%d, 4:%s %d bits, MBAFF=%d ACT=%d\n",
           ctx->width, ctx->height, ctx->is_444 ? "4:4" : "2:2",
           ctx->bit_depth, ctx->mbaff, ctx->act);

    // Newer format supports variable mb_scan_index sizes
    if (ctx->mb_height > 68 && ff_dnxhd_check_header_prefix_hr(header_prefix)) {
        ctx->data_offset = 0x170 + (ctx->mb_height << 2);
    } else {
        if (ctx->mb_height > 68 ||
            (ctx->mb_height << frame->interlaced_frame) > (ctx->height + 15) >> 4) {
            av_log(ctx->avctx, AV_LOG_ERROR,
                   "mb height too big: %d\n", ctx->mb_height);
            return AVERROR_INVALIDDATA;
        }
        ctx->data_offset = 0x280;
    }

    if (buf_size < ctx->data_offset) {
        av_log(ctx->avctx, AV_LOG_ERROR,
               "buffer too small (%d < %d).\n", buf_size, ctx->data_offset);
        return AVERROR_INVALIDDATA;
    }

    if (ctx->mb_height > FF_ARRAY_ELEMS(ctx->mb_scan_index)) {
        av_log(ctx->avctx, AV_LOG_ERROR,
               "mb_height too big (%d > %"SIZE_SPECIFIER").\n", ctx->mb_height, FF_ARRAY_ELEMS(ctx->mb_scan_index));
        return AVERROR_INVALIDDATA;
    }

    for (i = 0; i < ctx->mb_height; i++) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -298,13 +298,17 @@
     if (ctx->mb_height > 68 && ff_dnxhd_check_header_prefix_hr(header_prefix)) {
         ctx->data_offset = 0x170 + (ctx->mb_height << 2);
     } else {
-        if (ctx->mb_height > 68 ||
-            (ctx->mb_height << frame->interlaced_frame) > (ctx->height + 15) >> 4) {
+        if (ctx->mb_height > 68) {
             av_log(ctx->avctx, AV_LOG_ERROR,
                    "mb height too big: %d\n", ctx->mb_height);
             return AVERROR_INVALIDDATA;
         }
         ctx->data_offset = 0x280;
+    }
+    if ((ctx->mb_height << frame->interlaced_frame) > (ctx->height + 15) >> 4) {
+        av_log(ctx->avctx, AV_LOG_ERROR,
+                "mb height too big: %d\n", ctx->mb_height);
+        return AVERROR_INVALIDDATA;
     }
 
     if (buf_size < ctx->data_offset) {
```
