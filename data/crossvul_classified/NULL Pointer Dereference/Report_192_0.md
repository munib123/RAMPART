# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 192_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `192_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 241-281 of the vulnerable file.


    if (avctx->lowres==1) {
        c->idct_put  = ff_jref_idct4_put;
        c->idct_add  = ff_jref_idct4_add;
        c->idct      = ff_j_rev_dct4;
        c->perm_type = FF_IDCT_PERM_NONE;
    } else if (avctx->lowres==2) {
        c->idct_put  = ff_jref_idct2_put;
        c->idct_add  = ff_jref_idct2_add;
        c->idct      = ff_j_rev_dct2;
        c->perm_type = FF_IDCT_PERM_NONE;
    } else if (avctx->lowres==3) {
        c->idct_put  = ff_jref_idct1_put;
        c->idct_add  = ff_jref_idct1_add;
        c->idct      = ff_j_rev_dct1;
        c->perm_type = FF_IDCT_PERM_NONE;
    } else {
        if (avctx->bits_per_raw_sample == 10 || avctx->bits_per_raw_sample == 9) {
            /* 10-bit MPEG-4 Simple Studio Profile requires a higher precision IDCT
               However, it only uses idct_put */
            if (avctx->codec_id == AV_CODEC_ID_MPEG4 && avctx->profile == FF_PROFILE_MPEG4_SIMPLE_STUDIO)
                c->idct_put              = ff_simple_idct_put_int32_10bit;
            else {
                c->idct_put              = ff_simple_idct_put_int16_10bit;
                c->idct_add              = ff_simple_idct_add_int16_10bit;
                c->idct                  = ff_simple_idct_int16_10bit;
            }
            c->perm_type             = FF_IDCT_PERM_NONE;
        } else if (avctx->bits_per_raw_sample == 12) {
            c->idct_put              = ff_simple_idct_put_int16_12bit;
            c->idct_add              = ff_simple_idct_add_int16_12bit;
            c->idct                  = ff_simple_idct_int16_12bit;
            c->perm_type             = FF_IDCT_PERM_NONE;
        } else {
            if (avctx->idct_algo == FF_IDCT_INT) {
                c->idct_put  = ff_jref_idct_put;
                c->idct_add  = ff_jref_idct_add;
                c->idct      = ff_j_rev_dct;
                c->perm_type = FF_IDCT_PERM_LIBMPEG2;
#if CONFIG_FAANIDCT
            } else if (avctx->idct_algo == FF_IDCT_FAAN) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -258,7 +258,7 @@
         if (avctx->bits_per_raw_sample == 10 || avctx->bits_per_raw_sample == 9) {
             /* 10-bit MPEG-4 Simple Studio Profile requires a higher precision IDCT
                However, it only uses idct_put */
-            if (avctx->codec_id == AV_CODEC_ID_MPEG4 && avctx->profile == FF_PROFILE_MPEG4_SIMPLE_STUDIO)
+            if (c->mpeg4_studio_profile)
                 c->idct_put              = ff_simple_idct_put_int32_10bit;
             else {
                 c->idct_put              = ff_simple_idct_put_int16_10bit;
```
