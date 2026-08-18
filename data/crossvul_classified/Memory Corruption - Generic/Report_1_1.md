# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 1_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 33-73 of the vulnerable file.

#include <assert.h>

#include "global.h"
#include "getvlc.h"
#include "common_block.h"
#include "inter_prediction.h"

extern int zigzag16[16];
extern int zigzag64[64];
extern int zigzag256[256];

int YPOS, XPOS;

#undef TEMPLATE
#define TEMPLATE(func) (decoder_info->bitdepth == 8 ? func ## _lbd : func ## _hbd)

void read_sequence_header(decoder_info_t *decoder_info, stream_t *stream) {
  decoder_info->width = get_flc(16, stream);
  decoder_info->height = get_flc(16, stream);
  decoder_info->log2_sb_size = get_flc(3, stream);
  decoder_info->pb_split = get_flc(1, stream);
  decoder_info->tb_split_enable = get_flc(1, stream);
  decoder_info->max_num_ref = get_flc(2, stream) + 1;
  decoder_info->interp_ref = get_flc(2, stream);
  decoder_info->max_delta_qp = get_flc(1, stream);
  decoder_info->deblocking = get_flc(1, stream);
  decoder_info->clpf = get_flc(1, stream);
  decoder_info->use_block_contexts = get_flc(1, stream);
  decoder_info->bipred = get_flc(2, stream);
  decoder_info->qmtx = get_flc(1, stream);
  if (decoder_info->qmtx) {
    decoder_info->qmtx_offset = get_flc(6, stream) - 32;
  }
  decoder_info->subsample = get_flc(2, stream);
    decoder_info->subsample = // 0: 400  1: 420  2: 422  3: 444
    (decoder_info->subsample & 1) * 20 + (decoder_info->subsample & 2) * 22 +
    ((decoder_info->subsample & 3) == 3) * 2 + 400;
  decoder_info->num_reorder_pics = get_flc(4, stream);
  if (decoder_info->subsample != 400) {
    decoder_info->cfl_intra = get_flc(1, stream);
    decoder_info->cfl_inter = get_flc(1, stream);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -50,6 +50,7 @@
   decoder_info->width = get_flc(16, stream);
   decoder_info->height = get_flc(16, stream);
   decoder_info->log2_sb_size = get_flc(3, stream);
+  decoder_info->log2_sb_size = clip(decoder_info->log2_sb_size, log2i(MIN_BLOCK_SIZE), log2i(MAX_SB_SIZE));
   decoder_info->pb_split = get_flc(1, stream);
   decoder_info->tb_split_enable = get_flc(1, stream);
   decoder_info->max_num_ref = get_flc(2, stream) + 1;
```
