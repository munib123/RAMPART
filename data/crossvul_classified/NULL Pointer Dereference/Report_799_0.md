# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 799_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `799_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 471-511 of the vulnerable file.


    s->ps.sps = sps;
    s->ps.vps = (HEVCVPS*) s->ps.vps_list[s->ps.sps->vps_id]->data;

    return 0;

fail:
    pic_arrays_free(s);
    s->ps.sps = NULL;
    return ret;
}

static int hls_slice_header(HEVCContext *s)
{
    GetBitContext *gb = &s->HEVClc->gb;
    SliceHeader *sh   = &s->sh;
    int i, ret;

    // Coded parameters
    sh->first_slice_in_pic_flag = get_bits1(gb);
    if ((IS_IDR(s) || IS_BLA(s)) && sh->first_slice_in_pic_flag) {
        s->seq_decode = (s->seq_decode + 1) & 0xff;
        s->max_ra     = INT_MAX;
        if (IS_IDR(s))
            ff_hevc_clear_refs(s);
    }
    sh->no_output_of_prior_pics_flag = 0;
    if (IS_IRAP(s))
        sh->no_output_of_prior_pics_flag = get_bits1(gb);

    sh->pps_id = get_ue_golomb_long(gb);
    if (sh->pps_id >= HEVC_MAX_PPS_COUNT || !s->ps.pps_list[sh->pps_id]) {
        av_log(s->avctx, AV_LOG_ERROR, "PPS id out of range: %d\n", sh->pps_id);
        return AVERROR_INVALIDDATA;
    }
    if (!sh->first_slice_in_pic_flag &&
        s->ps.pps != (HEVCPPS*)s->ps.pps_list[sh->pps_id]->data) {
        av_log(s->avctx, AV_LOG_ERROR, "PPS changed between slices.\n");
        return AVERROR_INVALIDDATA;
    }
    s->ps.pps = (HEVCPPS*)s->ps.pps_list[sh->pps_id]->data;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -488,6 +488,11 @@
 
     // Coded parameters
     sh->first_slice_in_pic_flag = get_bits1(gb);
+    if (s->ref && sh->first_slice_in_pic_flag) {
+        av_log(s->avctx, AV_LOG_ERROR, "Two slices reporting being the first in the same frame.\n");
+        return 1; // This slice will be skiped later, do not corrupt state
+    }
+
     if ((IS_IDR(s) || IS_BLA(s)) && sh->first_slice_in_pic_flag) {
         s->seq_decode = (s->seq_decode + 1) & 0xff;
         s->max_ra     = INT_MAX;
@@ -2918,6 +2923,11 @@
         ret = hls_slice_header(s);
         if (ret < 0)
             return ret;
+        if (ret == 1) {
+            ret = AVERROR_INVALIDDATA;
+            goto fail;
+        }
+
 
         if (
             (s->avctx->skip_frame >= AVDISCARD_BIDIR && s->sh.slice_type == HEVC_SLICE_B) ||
@@ -2927,10 +2937,6 @@
         }
 
         if (s->sh.first_slice_in_pic_flag) {
-            if (s->ref) {
-                av_log(s->avctx, AV_LOG_ERROR, "Two slices reporting being the first in the same frame.\n");
-                goto fail;
-            }
             if (s->max_ra == INT_MAX) {
                 if (s->nal_unit_type == HEVC_NAL_CRA_NUT || IS_BLA(s)) {
                     s->max_ra = s->poc;
```
