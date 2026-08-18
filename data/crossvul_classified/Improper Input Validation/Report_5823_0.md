# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5823_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5823_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 353-393 of the vulnerable file.

    s->avctx->bits_per_raw_sample = s->precision;
    return 0;
}

/* get common part for COD and COC segments */
static int get_cox(Jpeg2000DecoderContext *s, Jpeg2000CodingStyle *c)
{
    uint8_t byte;

    if (bytestream2_get_bytes_left(&s->g) < 5)
        return AVERROR_INVALIDDATA;

    /*  nreslevels = number of resolution levels
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

    if (c->log2_cblk_width > 6 || c->log2_cblk_height > 6) {
        avpriv_request_sample(s->avctx, "cblk size > 64");
        return AVERROR_PATCHWELCOME;
    }

    c->cblk_style = bytestream2_get_byteu(&s->g);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -370,11 +370,18 @@
         return AVERROR_INVALIDDATA;
     }
 
+    if (c->nreslevels <= s->reduction_factor) {
+        /* we are forced to update reduction_factor as its requested value is
+           not compatible with this bitstream, and as we might have used it
+           already in setup earlier we have to fail this frame until
+           reinitialization is implemented */
+        av_log(s->avctx, AV_LOG_ERROR, "reduction_factor too large for this bitstream, max is %d\n", c->nreslevels - 1);
+        s->reduction_factor = c->nreslevels - 1;
+        return AVERROR(EINVAL);
+    }
+
     /* compute number of resolution levels to decode */
-    if (c->nreslevels < s->reduction_factor)
-        c->nreslevels2decode = 1;
-    else
-        c->nreslevels2decode = c->nreslevels - s->reduction_factor;
+    c->nreslevels2decode = c->nreslevels - s->reduction_factor;
 
     c->log2_cblk_width  = (bytestream2_get_byteu(&s->g) & 15) + 2; // cblk width
     c->log2_cblk_height = (bytestream2_get_byteu(&s->g) & 15) + 2; // cblk height
```
