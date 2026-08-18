# CrossVul Fix Pair: DEPRECATED: Code in c
**Pair ID:** 1454_0
**Vulnerability Class:** DEPRECATED- Code
**CWE:** CWE-17
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1454_0`)

## Vulnerability Information & PoC

## Description
DEPRECATED: Code

## Vulnerable Code
```c
Lines 4780-4825 of the vulnerable file.

	 * Round up offset. This is not fallocate, we neet to zero out
	 * blocks, so convert interior block aligned part of the range to
	 * unwritten and possibly manually zero out unaligned parts of the
	 * range.
	 */
	start = round_up(offset, 1 << blkbits);
	end = round_down((offset + len), 1 << blkbits);

	if (start < offset || end > offset + len)
		return -EINVAL;
	partial_begin = offset & ((1 << blkbits) - 1);
	partial_end = (offset + len) & ((1 << blkbits) - 1);

	lblk = start >> blkbits;
	max_blocks = (end >> blkbits);
	if (max_blocks < lblk)
		max_blocks = 0;
	else
		max_blocks -= lblk;

	flags = EXT4_GET_BLOCKS_CREATE_UNWRIT_EXT |
		EXT4_GET_BLOCKS_CONVERT_UNWRITTEN |
		EXT4_EX_NOCACHE;
	if (mode & FALLOC_FL_KEEP_SIZE)
		flags |= EXT4_GET_BLOCKS_KEEP_SIZE;

	mutex_lock(&inode->i_mutex);

	/*
	 * Indirect files do not support unwritten extnets
	 */
	if (!(ext4_test_inode_flag(inode, EXT4_INODE_EXTENTS))) {
		ret = -EOPNOTSUPP;
		goto out_mutex;
	}

	if (!(mode & FALLOC_FL_KEEP_SIZE) &&
	     offset + len > i_size_read(inode)) {
		new_size = offset + len;
		ret = inode_newsize_ok(inode, new_size);
		if (ret)
			goto out_mutex;
		/*
		 * If we have a partial block after EOF we have to allocate
		 * the entire block.
		 */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4797,12 +4797,6 @@
 	else
 		max_blocks -= lblk;
 
-	flags = EXT4_GET_BLOCKS_CREATE_UNWRIT_EXT |
-		EXT4_GET_BLOCKS_CONVERT_UNWRITTEN |
-		EXT4_EX_NOCACHE;
-	if (mode & FALLOC_FL_KEEP_SIZE)
-		flags |= EXT4_GET_BLOCKS_KEEP_SIZE;
-
 	mutex_lock(&inode->i_mutex);
 
 	/*
@@ -4819,15 +4813,28 @@
 		ret = inode_newsize_ok(inode, new_size);
 		if (ret)
 			goto out_mutex;
-		/*
-		 * If we have a partial block after EOF we have to allocate
-		 * the entire block.
-		 */
-		if (partial_end)
-			max_blocks += 1;
-	}
-
+	}
+
+	flags = EXT4_GET_BLOCKS_CREATE_UNWRIT_EXT;
+	if (mode & FALLOC_FL_KEEP_SIZE)
+		flags |= EXT4_GET_BLOCKS_KEEP_SIZE;
+
+	/* Preallocate the range including the unaligned edges */
+	if (partial_begin || partial_end) {
+		ret = ext4_alloc_file_blocks(file,
+				round_down(offset, 1 << blkbits) >> blkbits,
+				(round_up((offset + len), 1 << blkbits) -
+				 round_down(offset, 1 << blkbits)) >> blkbits,
+				new_size, flags, mode);
+		if (ret)
+			goto out_mutex;
+
+	}
+
+	/* Zero range excluding the unaligned edges */
 	if (max_blocks > 0) {
+		flags |= (EXT4_GET_BLOCKS_CONVERT_UNWRITTEN |
+			  EXT4_EX_NOCACHE);
 
 		/* Now release the pages and zero block aligned part of pages*/
 		truncate_pagecache_range(inode, start, end - 1);
```
