# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 3421_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3421_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 262-302 of the vulnerable file.

        return AVERROR_INVALIDDATA;
    if (c->bpp < 1)
        return AVERROR_INVALIDDATA;
    if (c->format != BIT_PLANAR && c->format != BIT_LINE && c->format != CHUNKY) {
        avpriv_request_sample(avctx, "Pixel format 0x%0x", c->format);
        return AVERROR_PATCHWELCOME;
    }

    if ((ret = ff_set_dimensions(avctx, w, h)) < 0)
        return ret;

    if (c->format == CHUNKY)
        aligned_width = avctx->width;
    else
        aligned_width = FFALIGN(c->avctx->width, 16);
    c->padded_bits  = aligned_width - c->avctx->width;
    if (c->video_size < aligned_width * avctx->height * (int64_t)c->bpp / 8)
        return AVERROR_INVALIDDATA;
    if (!encoding && c->palette_size && c->bpp <= 8 && c->format != CHUNKY) {
        avctx->pix_fmt = AV_PIX_FMT_PAL8;
    } else if (encoding == 1 && (c->bpp == 6 || c->bpp == 8)) {
        if (c->palette_size != (1 << (c->bpp - 1)))
            return AVERROR_INVALIDDATA;
        avctx->pix_fmt = AV_PIX_FMT_BGR24;
    } else if (!encoding && c->bpp == 24 && c->format == CHUNKY &&
               !c->palette_size) {
        avctx->pix_fmt = AV_PIX_FMT_RGB24;
    } else {
        avpriv_request_sample(avctx, "Encoding %d, bpp %d and format 0x%x",
                              encoding, c->bpp, c->format);
        return AVERROR_PATCHWELCOME;
    }

    if ((ret = ff_get_buffer(avctx, p, 0)) < 0)
        return ret;
    p->pict_type = AV_PICTURE_TYPE_I;

    if (encoding) {
        av_fast_padded_malloc(&c->new_video, &c->new_video_size,
                              h * w + AV_INPUT_BUFFER_PADDING_SIZE);
        if (!c->new_video)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -279,7 +279,7 @@
         return AVERROR_INVALIDDATA;
     if (!encoding && c->palette_size && c->bpp <= 8 && c->format != CHUNKY) {
         avctx->pix_fmt = AV_PIX_FMT_PAL8;
-    } else if (encoding == 1 && (c->bpp == 6 || c->bpp == 8)) {
+    } else if (encoding == 1 && (c->bpp == 6 || c->bpp == 8) && c->format != CHUNKY) {
         if (c->palette_size != (1 << (c->bpp - 1)))
             return AVERROR_INVALIDDATA;
         avctx->pix_fmt = AV_PIX_FMT_BGR24;
```
