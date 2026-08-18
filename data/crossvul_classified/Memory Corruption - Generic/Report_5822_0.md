# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5822_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5822_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 365-405 of the vulnerable file.

                   = number of decomposition level +1 */
    c->nreslevels = bytestream2_get_byteu(&s->g) + 1;
    if (c->nreslevels >= JPEG2000_MAX_RESLEVELS) {
        av_log(s->avctx, AV_LOG_ERROR, "nreslevels %d is invalid\n", c->nreslevels);
        return AVERROR_INVALIDDATA;
    }

    /* compute number of resolution levels to decode */
    if (c->nreslevels < s->reduction_factor)
        c->nreslevels2decode = 1;
    else
        c->nreslevels2decode = c->nreslevels - s->reduction_factor;

    c->log2_cblk_width  = (bytestream2_get_byteu(&s->g) & 15) + 2; // cblk width
    c->log2_cblk_height = (bytestream2_get_byteu(&s->g) & 15) + 2; // cblk height

    if (c->log2_cblk_width > 10 || c->log2_cblk_height > 10 ||
        c->log2_cblk_width + c->log2_cblk_height > 12) {
        av_log(s->avctx, AV_LOG_ERROR, "cblk size invalid\n");
        return AVERROR_INVALIDDATA;
    }

    c->cblk_style = bytestream2_get_byteu(&s->g);
    if (c->cblk_style != 0) { // cblk style
        av_log(s->avctx, AV_LOG_WARNING, "extra cblk styles %X\n", c->cblk_style);
    }
    c->transform = bytestream2_get_byteu(&s->g); // DWT transformation type
    /* set integer 9/7 DWT in case of BITEXACT flag */
    if ((s->avctx->flags & CODEC_FLAG_BITEXACT) && (c->transform == FF_DWT97))
        c->transform = FF_DWT97_INT;

    if (c->csty & JPEG2000_CSTY_PREC) {
        int i;
        for (i = 0; i < c->nreslevels; i++) {
            byte = bytestream2_get_byte(&s->g);
            c->log2_prec_widths[i]  =  byte       & 0x0F;    // precinct PPx
            c->log2_prec_heights[i] = (byte >> 4) & 0x0F;    // precinct PPy
        }
    } else {
        memset(c->log2_prec_widths , 15, sizeof(c->log2_prec_widths ));
        memset(c->log2_prec_heights, 15, sizeof(c->log2_prec_heights));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -382,6 +382,11 @@
         c->log2_cblk_width + c->log2_cblk_height > 12) {
         av_log(s->avctx, AV_LOG_ERROR, "cblk size invalid\n");
         return AVERROR_INVALIDDATA;
+    }
+
+    if (c->log2_cblk_width > 6 || c->log2_cblk_height > 6) {
+        avpriv_request_sample(s->avctx, "cblk size > 64");
+        return AVERROR_PATCHWELCOME;
     }
 
     c->cblk_style = bytestream2_get_byteu(&s->g);
@@ -1024,6 +1029,9 @@
     int clnpass_cnt = 0;
     int bpass_csty_symbol           = codsty->cblk_style & JPEG2000_CBLK_BYPASS;
     int vert_causal_ctx_csty_symbol = codsty->cblk_style & JPEG2000_CBLK_VSC;
+
+    av_assert0(width  <= JPEG2000_MAX_CBLKW);
+    av_assert0(height <= JPEG2000_MAX_CBLKH);
 
     for (y = 0; y < height; y++)
         memset(t1->data[y], 0, width * sizeof(**t1->data));
```
