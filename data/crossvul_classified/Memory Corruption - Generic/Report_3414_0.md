# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 3414_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3414_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 140-180 of the vulnerable file.

        av_log(avctx, AV_LOG_ERROR, "invalid bytes per scan-line\n");
        return AVERROR_INVALIDDATA;
    }

    if (bytestream2_get_bytes_left(&gb) < ncolors * XWD_CMAP_SIZE + (uint64_t)avctx->height * lsize) {
        av_log(avctx, AV_LOG_ERROR, "input buffer too small\n");
        return AVERROR_INVALIDDATA;
    }

    if (pixformat != XWD_Z_PIXMAP) {
        avpriv_report_missing_feature(avctx, "Pixmap format %"PRIu32, pixformat);
        return AVERROR_PATCHWELCOME;
    }

    avctx->pix_fmt = AV_PIX_FMT_NONE;
    switch (vclass) {
    case XWD_STATIC_GRAY:
    case XWD_GRAY_SCALE:
        if (bpp != 1 && bpp != 8)
            return AVERROR_INVALIDDATA;
        if (pixdepth == 1) {
            avctx->pix_fmt = AV_PIX_FMT_MONOWHITE;
        } else if (pixdepth == 8) {
            avctx->pix_fmt = AV_PIX_FMT_GRAY8;
        }
        break;
    case XWD_STATIC_COLOR:
    case XWD_PSEUDO_COLOR:
        if (bpp == 8)
            avctx->pix_fmt = AV_PIX_FMT_PAL8;
        break;
    case XWD_TRUE_COLOR:
    case XWD_DIRECT_COLOR:
        if (bpp != 16 && bpp != 24 && bpp != 32)
            return AVERROR_INVALIDDATA;
        if (bpp == 16 && pixdepth == 15) {
            if (rgb[0] == 0x7C00 && rgb[1] == 0x3E0 && rgb[2] == 0x1F)
                avctx->pix_fmt = be ? AV_PIX_FMT_RGB555BE : AV_PIX_FMT_RGB555LE;
            else if (rgb[0] == 0x1F && rgb[1] == 0x3E0 && rgb[2] == 0x7C00)
                avctx->pix_fmt = be ? AV_PIX_FMT_BGR555BE : AV_PIX_FMT_BGR555LE;
        } else if (bpp == 16 && pixdepth == 16) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -157,9 +157,9 @@
     case XWD_GRAY_SCALE:
         if (bpp != 1 && bpp != 8)
             return AVERROR_INVALIDDATA;
-        if (pixdepth == 1) {
+        if (bpp == 1 && pixdepth == 1) {
             avctx->pix_fmt = AV_PIX_FMT_MONOWHITE;
-        } else if (pixdepth == 8) {
+        } else if (bpp == 8 && pixdepth == 8) {
             avctx->pix_fmt = AV_PIX_FMT_GRAY8;
         }
         break;
```
