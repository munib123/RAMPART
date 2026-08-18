# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 3295_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3295_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 125-165 of the vulnerable file.

    if (bits_per_plane > 8 || bpp < 1 || bpp > 32) {
        avpriv_request_sample(avctx, "Unsupported bit depth");
        return AVERROR_PATCHWELCOME;
    }

    if (bytestream2_peek_byte(&s->g) == 0xFF || bpp == 1 || bpp == 4 || bpp == 8) {
        bytestream2_skip(&s->g, 2);
        etype = bytestream2_get_le16(&s->g);
        esize = bytestream2_get_le16(&s->g);
        if (bytestream2_get_bytes_left(&s->g) < esize)
            return AVERROR_INVALIDDATA;
    } else {
        etype = -1;
        esize = 0;
    }

    avctx->pix_fmt = AV_PIX_FMT_PAL8;

    if (av_image_check_size(s->width, s->height, 0, avctx) < 0)
        return -1;
    if (s->width != avctx->width && s->height != avctx->height) {
        ret = ff_set_dimensions(avctx, s->width, s->height);
        if (ret < 0)
            return ret;
    }

    if ((ret = ff_get_buffer(avctx, frame, 0)) < 0)
        return ret;
    memset(frame->data[0], 0, s->height * frame->linesize[0]);
    frame->pict_type           = AV_PICTURE_TYPE_I;
    frame->palette_has_changed = 1;

    pos_after_pal = bytestream2_tell(&s->g) + esize;
    palette = (uint32_t*)frame->data[1];
    if (etype == 1 && esize > 1 && bytestream2_peek_byte(&s->g) < 6) {
        int idx = bytestream2_get_byte(&s->g);
        npal = 4;
        for (i = 0; i < npal; i++)
            palette[i] = ff_cga_palette[ cga_mode45_index[idx][i] ];
    } else if (etype == 2) {
        npal = FFMIN(esize, 16);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -142,7 +142,7 @@
 
     if (av_image_check_size(s->width, s->height, 0, avctx) < 0)
         return -1;
-    if (s->width != avctx->width && s->height != avctx->height) {
+    if (s->width != avctx->width || s->height != avctx->height) {
         ret = ff_set_dimensions(avctx, s->width, s->height);
         if (ret < 0)
             return ret;
```
