# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 3297_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3297_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 359-399 of the vulnerable file.

        w_align = 16; //FIXME assume 16 pixel per macroblock
        h_align = 16 * 2; // interlaced needs 2 macroblocks height
        break;
    case AV_PIX_FMT_YUV411P:
    case AV_PIX_FMT_YUVJ411P:
    case AV_PIX_FMT_UYYVYY411:
        w_align = 32;
        h_align = 16 * 2;
        break;
    case AV_PIX_FMT_YUV410P:
        if (s->codec_id == AV_CODEC_ID_SVQ1) {
            w_align = 64;
            h_align = 64;
        }
        break;
    case AV_PIX_FMT_RGB555:
        if (s->codec_id == AV_CODEC_ID_RPZA) {
            w_align = 4;
            h_align = 4;
        }
        break;
    case AV_PIX_FMT_PAL8:
    case AV_PIX_FMT_BGR8:
    case AV_PIX_FMT_RGB8:
        if (s->codec_id == AV_CODEC_ID_SMC ||
            s->codec_id == AV_CODEC_ID_CINEPAK) {
            w_align = 4;
            h_align = 4;
        }
        if (s->codec_id == AV_CODEC_ID_JV) {
            w_align = 8;
            h_align = 8;
        }
        break;
    case AV_PIX_FMT_BGR24:
        if ((s->codec_id == AV_CODEC_ID_MSZH) ||
            (s->codec_id == AV_CODEC_ID_ZLIB)) {
            w_align = 4;
            h_align = 4;
        }
        break;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -376,6 +376,10 @@
             w_align = 4;
             h_align = 4;
         }
+        if (s->codec_id == AV_CODEC_ID_INTERPLAY_VIDEO) {
+            w_align = 8;
+            h_align = 8;
+        }
         break;
     case AV_PIX_FMT_PAL8:
     case AV_PIX_FMT_BGR8:
@@ -385,7 +389,8 @@
             w_align = 4;
             h_align = 4;
         }
-        if (s->codec_id == AV_CODEC_ID_JV) {
+        if (s->codec_id == AV_CODEC_ID_JV ||
+            s->codec_id == AV_CODEC_ID_INTERPLAY_VIDEO) {
             w_align = 8;
             h_align = 8;
         }
```
