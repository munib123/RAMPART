# CrossVul Fix Pair: Improper Validation of Array Index in c
**Pair ID:** 1182_0
**Vulnerability Class:** Improper Validation of Array Index
**CWE:** CWE-129
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1182_0`)

## Vulnerability Information & PoC

## Description
Improper Validation of Array Index - The product uses untrusted input when calculating or using an array index, but the product does not validate or incorrectly validates the index to ensure the index references a valid position withi...

## Vulnerable Code
```c
Lines 130-170 of the vulnerable file.

    if (s->avctx->extradata_size != VQA_HEADER_SIZE) {
        av_log(s->avctx, AV_LOG_ERROR, "expected extradata size of %d\n", VQA_HEADER_SIZE);
        return AVERROR(EINVAL);
    }

    /* load up the VQA parameters from the header */
    s->vqa_version = s->avctx->extradata[0];
    switch (s->vqa_version) {
    case 1:
    case 2:
        break;
    case 3:
        avpriv_report_missing_feature(avctx, "VQA Version %d", s->vqa_version);
        return AVERROR_PATCHWELCOME;
    default:
        avpriv_request_sample(avctx, "VQA Version %i", s->vqa_version);
        return AVERROR_PATCHWELCOME;
    }
    s->width = AV_RL16(&s->avctx->extradata[6]);
    s->height = AV_RL16(&s->avctx->extradata[8]);
    if ((ret = av_image_check_size(s->width, s->height, 0, avctx)) < 0) {
        s->width= s->height= 0;
        return ret;
    }
    s->vector_width = s->avctx->extradata[10];
    s->vector_height = s->avctx->extradata[11];
    s->partial_count = s->partial_countdown = s->avctx->extradata[13];

    /* the vector dimensions have to meet very stringent requirements */
    if ((s->vector_width != 4) ||
        ((s->vector_height != 2) && (s->vector_height != 4))) {
        /* return without further initialization */
        return AVERROR_INVALIDDATA;
    }

    if (s->width % s->vector_width || s->height % s->vector_height) {
        av_log(avctx, AV_LOG_ERROR, "Image size not multiple of block size\n");
        return AVERROR_INVALIDDATA;
    }

    /* allocate codebooks */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -147,7 +147,7 @@
     }
     s->width = AV_RL16(&s->avctx->extradata[6]);
     s->height = AV_RL16(&s->avctx->extradata[8]);
-    if ((ret = av_image_check_size(s->width, s->height, 0, avctx)) < 0) {
+    if ((ret = ff_set_dimensions(avctx, s->width, s->height)) < 0) {
         s->width= s->height= 0;
         return ret;
     }
```
