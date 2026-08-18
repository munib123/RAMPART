# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 651_2
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `651_2`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 2368-2408 of the vulnerable file.

		}
		break;
	}

	sps->profile_idc = profile_idc;
	sps->level_idc = level_idc;
	sps->prof_compat = pcomp;
	sps->log2_max_frame_num = bs_get_ue(bs) + 4;
	sps->poc_type = bs_get_ue(bs);
	sps->chroma_format = chroma_format_idc;
	sps->luma_bit_depth_m8 = luma_bd;
	sps->chroma_bit_depth_m8 = chroma_bd;

	if (sps->poc_type == 0) {
		sps->log2_max_poc_lsb = bs_get_ue(bs) + 4;
	} else if(sps->poc_type == 1) {
		sps->delta_pic_order_always_zero_flag = gf_bs_read_int(bs, 1);
		sps->offset_for_non_ref_pic = bs_get_se(bs);
		sps->offset_for_top_to_bottom_field = bs_get_se(bs);
		sps->poc_cycle_length = bs_get_ue(bs);
		for(i=0; i<sps->poc_cycle_length; i++) sps->offset_for_ref_frame[i] = bs_get_se(bs);
	}
	if (sps->poc_type > 2) {
		sps_id = -1;
		goto exit;
	}
	sps->max_num_ref_frames = bs_get_ue(bs); 
	sps->gaps_in_frame_num_value_allowed_flag = gf_bs_read_int(bs, 1); 
	mb_width = bs_get_ue(bs) + 1;
	mb_height= bs_get_ue(bs) + 1;

	sps->frame_mbs_only_flag = gf_bs_read_int(bs, 1);

	sps->width = mb_width * 16;
	sps->height = (2-sps->frame_mbs_only_flag) * mb_height * 16;
	
	if (!sps->frame_mbs_only_flag) sps->mb_adaptive_frame_field_flag = gf_bs_read_int(bs, 1);
	gf_bs_read_int(bs, 1); /*direct_8x8_inference_flag*/
	
	if (gf_bs_read_int(bs, 1)) { /*crop*/
		int CropUnitX, CropUnitY, SubWidthC = -1, SubHeightC = -1;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2385,6 +2385,10 @@
 		sps->offset_for_non_ref_pic = bs_get_se(bs);
 		sps->offset_for_top_to_bottom_field = bs_get_se(bs);
 		sps->poc_cycle_length = bs_get_ue(bs);
+		if (sps->poc_cycle_length > ARRAY_LENGTH(sps->offset_for_ref_frame)) {
+			GF_LOG(GF_LOG_ERROR, GF_LOG_CODING, ("[avc-h264] offset_for_ref_frame overflow from poc_cycle_length\n"));
+			goto exit;
+		}
 		for(i=0; i<sps->poc_cycle_length; i++) sps->offset_for_ref_frame[i] = bs_get_se(bs);
 	}
 	if (sps->poc_type > 2) {
```
