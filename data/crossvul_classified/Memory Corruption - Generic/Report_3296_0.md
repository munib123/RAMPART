# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 3296_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3296_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 755-795 of the vulnerable file.

    n = length / 3;
    for (i = 0; i < n; i++) {
        r = bytestream2_get_byte(&s->gb);
        g = bytestream2_get_byte(&s->gb);
        b = bytestream2_get_byte(&s->gb);
        s->palette[i] = (0xFFU << 24) | (r << 16) | (g << 8) | b;
    }
    for (; i < 256; i++)
        s->palette[i] = (0xFFU << 24);
    s->state |= PNG_PLTE;
    bytestream2_skip(&s->gb, 4);     /* crc */

    return 0;
}

static int decode_trns_chunk(AVCodecContext *avctx, PNGDecContext *s,
                             uint32_t length)
{
    int v, i;

    if (s->color_type == PNG_COLOR_TYPE_PALETTE) {
        if (length > 256 || !(s->state & PNG_PLTE))
            return AVERROR_INVALIDDATA;

        for (i = 0; i < length; i++) {
            v = bytestream2_get_byte(&s->gb);
            s->palette[i] = (s->palette[i] & 0x00ffffff) | (v << 24);
        }
    } else if (s->color_type == PNG_COLOR_TYPE_GRAY || s->color_type == PNG_COLOR_TYPE_RGB) {
        if ((s->color_type == PNG_COLOR_TYPE_GRAY && length != 2) ||
            (s->color_type == PNG_COLOR_TYPE_RGB && length != 6))
            return AVERROR_INVALIDDATA;

        for (i = 0; i < length / 2; i++) {
            /* only use the least significant bits */
            v = av_mod_uintp2(bytestream2_get_be16(&s->gb), s->bit_depth);

            if (s->bit_depth > 8)
                AV_WB16(&s->transparent_color_be[2 * i], v);
            else
                s->transparent_color_be[i] = v;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -772,6 +772,16 @@
 {
     int v, i;
 
+    if (!(s->state & PNG_IHDR)) {
+        av_log(avctx, AV_LOG_ERROR, "trns before IHDR\n");
+        return AVERROR_INVALIDDATA;
+    }
+
+    if (s->state & PNG_IDAT) {
+        av_log(avctx, AV_LOG_ERROR, "trns after IDAT\n");
+        return AVERROR_INVALIDDATA;
+    }
+
     if (s->color_type == PNG_COLOR_TYPE_PALETTE) {
         if (length > 256 || !(s->state & PNG_PLTE))
             return AVERROR_INVALIDDATA;
@@ -782,7 +792,8 @@
         }
     } else if (s->color_type == PNG_COLOR_TYPE_GRAY || s->color_type == PNG_COLOR_TYPE_RGB) {
         if ((s->color_type == PNG_COLOR_TYPE_GRAY && length != 2) ||
-            (s->color_type == PNG_COLOR_TYPE_RGB && length != 6))
+            (s->color_type == PNG_COLOR_TYPE_RGB && length != 6) ||
+            s->bit_depth == 1)
             return AVERROR_INVALIDDATA;
 
         for (i = 0; i < length / 2; i++) {
@@ -1242,6 +1253,8 @@
         size_t raw_bpp = s->bpp - byte_depth;
         unsigned x, y;
 
+        av_assert0(s->bit_depth > 1);
+
         for (y = 0; y < s->height; ++y) {
             uint8_t *row = &s->image_buf[s->image_linesize * y];
 
```
