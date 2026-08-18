# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5824_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5824_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 563-603 of the vulnerable file.

               f->avctx->bits_per_raw_sample,
               f->chroma_planes, f->chroma_h_shift, f->chroma_v_shift,
               f->transparency,
               f->num_h_slices, f->num_v_slices,
               f->quant_table_count,
               f->ec,
               f->intra
              );
    return 0;
}

static int read_header(FFV1Context *f)
{
    uint8_t state[CONTEXT_SIZE];
    int i, j, context_count = -1; //-1 to avoid warning
    RangeCoder *const c = &f->slice_context[0]->c;

    memset(state, 128, sizeof(state));

    if (f->version < 2) {
        int chroma_planes, chroma_h_shift, chroma_v_shift, transparency;
        unsigned v= get_symbol(c, state, 0);
        if (v >= 2) {
            av_log(f->avctx, AV_LOG_ERROR, "invalid version %d in ver01 header\n", v);
            return AVERROR_INVALIDDATA;
        }
        f->version = v;
        f->ac      = f->avctx->coder_type = get_symbol(c, state, 0);
        if (f->ac > 1) {
            for (i = 1; i < 256; i++)
                f->state_transition[i] = get_symbol(c, state, 1) + c->one_state[i];
        }

        f->colorspace = get_symbol(c, state, 0); //YUV cs type

        if (f->version > 0)
            f->avctx->bits_per_raw_sample = get_symbol(c, state, 0);

        chroma_planes  = get_rac(c, state);
        chroma_h_shift = get_symbol(c, state, 0);
        chroma_v_shift = get_symbol(c, state, 0);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -580,7 +580,7 @@
     memset(state, 128, sizeof(state));
 
     if (f->version < 2) {
-        int chroma_planes, chroma_h_shift, chroma_v_shift, transparency;
+        int chroma_planes, chroma_h_shift, chroma_v_shift, transparency, colorspace, bits_per_raw_sample;
         unsigned v= get_symbol(c, state, 0);
         if (v >= 2) {
             av_log(f->avctx, AV_LOG_ERROR, "invalid version %d in ver01 header\n", v);
@@ -593,18 +593,17 @@
                 f->state_transition[i] = get_symbol(c, state, 1) + c->one_state[i];
         }
 
-        f->colorspace = get_symbol(c, state, 0); //YUV cs type
-
-        if (f->version > 0)
-            f->avctx->bits_per_raw_sample = get_symbol(c, state, 0);
-
+        colorspace     = get_symbol(c, state, 0); //YUV cs type
+        bits_per_raw_sample = f->version > 0 ? get_symbol(c, state, 0) : f->avctx->bits_per_raw_sample;
         chroma_planes  = get_rac(c, state);
         chroma_h_shift = get_symbol(c, state, 0);
         chroma_v_shift = get_symbol(c, state, 0);
         transparency   = get_rac(c, state);
 
         if (f->plane_count) {
-            if (   chroma_planes != f->chroma_planes
+            if (   colorspace    != f->colorspace
+                || bits_per_raw_sample != f->avctx->bits_per_raw_sample
+                || chroma_planes != f->chroma_planes
                 || chroma_h_shift!= f->chroma_h_shift
                 || chroma_v_shift!= f->chroma_v_shift
                 || transparency  != f->transparency) {
@@ -613,6 +612,8 @@
             }
         }
 
+        f->colorspace     = colorspace;
+        f->avctx->bits_per_raw_sample = bits_per_raw_sample;
         f->chroma_planes  = chroma_planes;
         f->chroma_h_shift = chroma_h_shift;
         f->chroma_v_shift = chroma_v_shift;
```
