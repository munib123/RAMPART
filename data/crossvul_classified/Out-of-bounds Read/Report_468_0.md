# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 468_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `468_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 2850-2890 of the vulnerable file.

    if (s->vo_type == 0 && ctx->vol_control_parameters == 0 &&
        ctx->divx_version == -1 && s->picture_number == 0) {
        av_log(s->avctx, AV_LOG_WARNING,
               "looks like this file was encoded with (divx4/(old)xvid/opendivx) -> forcing low_delay flag\n");
        s->low_delay = 1;
    }

    s->picture_number++;  // better than pic number==0 always ;)

    // FIXME add short header support
    s->y_dc_scale_table = ff_mpeg4_y_dc_scale_table;
    s->c_dc_scale_table = ff_mpeg4_c_dc_scale_table;

    if (s->workaround_bugs & FF_BUG_EDGE) {
        s->h_edge_pos = s->width;
        s->v_edge_pos = s->height;
    }
    return 0;
}

static void read_quant_matrix_ext(MpegEncContext *s, GetBitContext *gb)
{
    int i, j, v;

    if (get_bits1(gb)) {
        /* intra_quantiser_matrix */
        for (i = 0; i < 64; i++) {
            v = get_bits(gb, 8);
            j = s->idsp.idct_permutation[ff_zigzag_direct[i]];
            s->intra_matrix[j]        = v;
            s->chroma_intra_matrix[j] = v;
        }
    }

    if (get_bits1(gb)) {
        /* non_intra_quantiser_matrix */
        for (i = 0; i < 64; i++) {
            get_bits(gb, 8);
        }
    }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2867,11 +2867,13 @@
     return 0;
 }
 
-static void read_quant_matrix_ext(MpegEncContext *s, GetBitContext *gb)
+static int read_quant_matrix_ext(MpegEncContext *s, GetBitContext *gb)
 {
     int i, j, v;
 
     if (get_bits1(gb)) {
+        if (get_bits_left(gb) < 64*8)
+            return AVERROR_INVALIDDATA;
         /* intra_quantiser_matrix */
         for (i = 0; i < 64; i++) {
             v = get_bits(gb, 8);
@@ -2882,6 +2884,8 @@
     }
 
     if (get_bits1(gb)) {
+        if (get_bits_left(gb) < 64*8)
+            return AVERROR_INVALIDDATA;
         /* non_intra_quantiser_matrix */
         for (i = 0; i < 64; i++) {
             get_bits(gb, 8);
@@ -2889,6 +2893,8 @@
     }
 
     if (get_bits1(gb)) {
+        if (get_bits_left(gb) < 64*8)
+            return AVERROR_INVALIDDATA;
         /* chroma_intra_quantiser_matrix */
         for (i = 0; i < 64; i++) {
             v = get_bits(gb, 8);
@@ -2898,6 +2904,8 @@
     }
 
     if (get_bits1(gb)) {
+        if (get_bits_left(gb) < 64*8)
+            return AVERROR_INVALIDDATA;
         /* chroma_non_intra_quantiser_matrix */
         for (i = 0; i < 64; i++) {
             get_bits(gb, 8);
@@ -2905,6 +2913,7 @@
     }
 
     next_start_code_studio(gb);
+    return 0;
 }
 
 static void extension_and_user_data(MpegEncContext *s, GetBitContext *gb, int id)
```
