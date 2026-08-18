# CrossVul Fix Pair: Improper Validation of Array Index in c
**Pair ID:** 2552_0
**Vulnerability Class:** Improper Validation of Array Index
**CWE:** CWE-129
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2552_0`)

## Vulnerability Information & PoC

## Description
Improper Validation of Array Index - The product uses untrusted input when calculating or using an array index, but the product does not validate or incorrectly validates the index to ensure the index references a valid position withi...

## Vulnerable Code
```c
Lines 1504-1544 of the vulnerable file.

	if (le32_to_cpu(raw_super->segment_count) > F2FS_MAX_SEGMENT) {
		f2fs_msg(sb, KERN_INFO,
			"Invalid segment count (%u)",
			le32_to_cpu(raw_super->segment_count));
		return 1;
	}

	/* check CP/SIT/NAT/SSA/MAIN_AREA area boundary */
	if (sanity_check_area_boundary(sbi, bh))
		return 1;

	return 0;
}

int sanity_check_ckpt(struct f2fs_sb_info *sbi)
{
	unsigned int total, fsmeta;
	struct f2fs_super_block *raw_super = F2FS_RAW_SUPER(sbi);
	struct f2fs_checkpoint *ckpt = F2FS_CKPT(sbi);
	unsigned int ovp_segments, reserved_segments;

	total = le32_to_cpu(raw_super->segment_count);
	fsmeta = le32_to_cpu(raw_super->segment_count_ckpt);
	fsmeta += le32_to_cpu(raw_super->segment_count_sit);
	fsmeta += le32_to_cpu(raw_super->segment_count_nat);
	fsmeta += le32_to_cpu(ckpt->rsvd_segment_count);
	fsmeta += le32_to_cpu(raw_super->segment_count_ssa);

	if (unlikely(fsmeta >= total))
		return 1;

	ovp_segments = le32_to_cpu(ckpt->overprov_segment_count);
	reserved_segments = le32_to_cpu(ckpt->rsvd_segment_count);

	if (unlikely(fsmeta < F2FS_MIN_SEGMENTS ||
			ovp_segments == 0 || reserved_segments == 0)) {
		f2fs_msg(sbi->sb, KERN_ERR,
			"Wrong layout: check mkfs.f2fs version");
		return 1;
	}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1521,6 +1521,8 @@
 	struct f2fs_super_block *raw_super = F2FS_RAW_SUPER(sbi);
 	struct f2fs_checkpoint *ckpt = F2FS_CKPT(sbi);
 	unsigned int ovp_segments, reserved_segments;
+	unsigned int main_segs, blocks_per_seg;
+	int i;
 
 	total = le32_to_cpu(raw_super->segment_count);
 	fsmeta = le32_to_cpu(raw_super->segment_count_ckpt);
@@ -1540,6 +1542,20 @@
 		f2fs_msg(sbi->sb, KERN_ERR,
 			"Wrong layout: check mkfs.f2fs version");
 		return 1;
+	}
+
+	main_segs = le32_to_cpu(raw_super->segment_count_main);
+	blocks_per_seg = sbi->blocks_per_seg;
+
+	for (i = 0; i < NR_CURSEG_NODE_TYPE; i++) {
+		if (le32_to_cpu(ckpt->cur_node_segno[i]) >= main_segs ||
+			le16_to_cpu(ckpt->cur_node_blkoff[i]) >= blocks_per_seg)
+			return 1;
+	}
+	for (i = 0; i < NR_CURSEG_DATA_TYPE; i++) {
+		if (le32_to_cpu(ckpt->cur_data_segno[i]) >= main_segs ||
+			le16_to_cpu(ckpt->cur_data_blkoff[i]) >= blocks_per_seg)
+			return 1;
 	}
 
 	if (unlikely(f2fs_cp_error(sbi))) {
```
