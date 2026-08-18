# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 192_1
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `192_1`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 78-118 of the vulnerable file.

     */
    void (*idct_add)(uint8_t *dest /* align 8 */,
                     ptrdiff_t line_size, int16_t *block /* align 16 */);

    /**
     * IDCT input permutation.
     * Several optimized IDCTs need a permutated input (relative to the
     * normal order of the reference IDCT).
     * This permutation must be performed before the idct_put/add.
     * Note, normally this can be merged with the zigzag/alternate scan<br>
     * An example to avoid confusion:
     * - (->decode coeffs -> zigzag reorder -> dequant -> reference IDCT -> ...)
     * - (x -> reference DCT -> reference IDCT -> x)
     * - (x -> reference DCT -> simple_mmx_perm = idct_permutation
     *    -> simple_idct_mmx -> x)
     * - (-> decode coeffs -> zigzag reorder -> simple_mmx_perm -> dequant
     *    -> simple_idct_mmx -> ...)
     */
    uint8_t idct_permutation[64];
    enum idct_permutation_type perm_type;
} IDCTDSPContext;

void ff_put_pixels_clamped_c(const int16_t *block, uint8_t *av_restrict pixels,
                             ptrdiff_t line_size);
void ff_add_pixels_clamped_c(const int16_t *block, uint8_t *av_restrict pixels,
                             ptrdiff_t line_size);

void ff_idctdsp_init(IDCTDSPContext *c, AVCodecContext *avctx);

void ff_idctdsp_init_aarch64(IDCTDSPContext *c, AVCodecContext *avctx,
                             unsigned high_bit_depth);
void ff_idctdsp_init_alpha(IDCTDSPContext *c, AVCodecContext *avctx,
                           unsigned high_bit_depth);
void ff_idctdsp_init_arm(IDCTDSPContext *c, AVCodecContext *avctx,
                         unsigned high_bit_depth);
void ff_idctdsp_init_ppc(IDCTDSPContext *c, AVCodecContext *avctx,
                         unsigned high_bit_depth);
void ff_idctdsp_init_x86(IDCTDSPContext *c, AVCodecContext *avctx,
                         unsigned high_bit_depth);
void ff_idctdsp_init_mips(IDCTDSPContext *c, AVCodecContext *avctx,
                          unsigned high_bit_depth);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -95,6 +95,8 @@
      */
     uint8_t idct_permutation[64];
     enum idct_permutation_type perm_type;
+
+    int mpeg4_studio_profile;
 } IDCTDSPContext;
 
 void ff_put_pixels_clamped_c(const int16_t *block, uint8_t *av_restrict pixels,
```
