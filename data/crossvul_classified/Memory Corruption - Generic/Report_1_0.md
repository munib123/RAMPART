# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 1_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 633-663 of the vulnerable file.

  TEMPLATE(find_block_contexts)(yposY, xposY, height, width, size, decoder_info->deblock_data, &block_context, decoder_info->use_block_contexts);
  decoder_info->block_context = &block_context;

  split_flag = decode_super_mode(decoder_info,size,decode_this_size);
  mode = decoder_info->mode;
  
  /* Read delta_qp and set block-level qp */
  if (size == (1<<decoder_info->log2_sb_size) && (split_flag || mode != MODE_SKIP) && decoder_info->max_delta_qp > 0) {
    /* Read delta_qp */
    int delta_qp = read_delta_qp(stream);
    int prev_qp;
    if (yposY == 0 && xposY == 0)
      prev_qp = decoder_info->frame_info.qp;
    else
      prev_qp = decoder_info->frame_info.qpb;
    decoder_info->frame_info.qpb = prev_qp + delta_qp;
  }

  decoder_info->bit_count.super_mode[decoder_info->bit_count.stat_frame_type] += (stream->bitcnt - bit_start);

  if (split_flag){
    int new_size = size/2;
    TEMPLATE(process_block_dec)(decoder_info,new_size,yposY+0*new_size,xposY+0*new_size,sub);
    TEMPLATE(process_block_dec)(decoder_info,new_size,yposY+1*new_size,xposY+0*new_size,sub);
    TEMPLATE(process_block_dec)(decoder_info,new_size,yposY+0*new_size,xposY+1*new_size,sub);
    TEMPLATE(process_block_dec)(decoder_info,new_size,yposY+1*new_size,xposY+1*new_size,sub);
  }
  else if (decode_this_size || decode_rectangular_size){
    decode_block(decoder_info,size,yposY,xposY,sub);
  }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -650,7 +650,7 @@
 
   decoder_info->bit_count.super_mode[decoder_info->bit_count.stat_frame_type] += (stream->bitcnt - bit_start);
 
-  if (split_flag){
+  if (split_flag && size >= MIN_BLOCK_SIZE){
     int new_size = size/2;
     TEMPLATE(process_block_dec)(decoder_info,new_size,yposY+0*new_size,xposY+0*new_size,sub);
     TEMPLATE(process_block_dec)(decoder_info,new_size,yposY+1*new_size,xposY+0*new_size,sub);
```
