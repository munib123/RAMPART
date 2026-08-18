# CrossVul Fix Pair: Data Processing Errors in c
**Pair ID:** 1453_1
**Vulnerability Class:** Data Processing Errors
**CWE:** CWE-19
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1453_1`)

## Vulnerability Information & PoC

## Description
Data Processing Errors

## Vulnerable Code
```c
Lines 1212-1252 of the vulnerable file.

	 * which blocks they should be as we might allocate more blocks
	 * as part of this transaction (a split operation for example).
	 */
	if (entry->flags & XFS_ATTR_LOCAL) {
		name_loc = xfs_attr3_leaf_name_local(leaf, args->index);
		name_loc->namelen = args->namelen;
		name_loc->valuelen = cpu_to_be16(args->valuelen);
		memcpy((char *)name_loc->nameval, args->name, args->namelen);
		memcpy((char *)&name_loc->nameval[args->namelen], args->value,
				   be16_to_cpu(name_loc->valuelen));
	} else {
		name_rmt = xfs_attr3_leaf_name_remote(leaf, args->index);
		name_rmt->namelen = args->namelen;
		memcpy((char *)name_rmt->name, args->name, args->namelen);
		entry->flags |= XFS_ATTR_INCOMPLETE;
		/* just in case */
		name_rmt->valuelen = 0;
		name_rmt->valueblk = 0;
		args->rmtblkno = 1;
		args->rmtblkcnt = xfs_attr3_rmt_blocks(mp, args->valuelen);
	}
	xfs_trans_log_buf(args->trans, bp,
	     XFS_DA_LOGRANGE(leaf, xfs_attr3_leaf_name(leaf, args->index),
				   xfs_attr_leaf_entsize(leaf, args->index)));

	/*
	 * Update the control info for this leaf node
	 */
	if (be16_to_cpu(entry->nameidx) < ichdr->firstused)
		ichdr->firstused = be16_to_cpu(entry->nameidx);

	ASSERT(ichdr->firstused >= ichdr->count * sizeof(xfs_attr_leaf_entry_t)
					+ xfs_attr3_leaf_hdr_size(leaf));
	tmp = (ichdr->count - 1) * sizeof(xfs_attr_leaf_entry_t)
					+ xfs_attr3_leaf_hdr_size(leaf);

	for (i = 0; i < XFS_ATTR_LEAF_MAPSIZE; i++) {
		if (ichdr->freemap[i].base == tmp) {
			ichdr->freemap[i].base += sizeof(xfs_attr_leaf_entry_t);
			ichdr->freemap[i].size -= sizeof(xfs_attr_leaf_entry_t);
		}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1229,6 +1229,7 @@
 		name_rmt->valueblk = 0;
 		args->rmtblkno = 1;
 		args->rmtblkcnt = xfs_attr3_rmt_blocks(mp, args->valuelen);
+		args->rmtvaluelen = args->valuelen;
 	}
 	xfs_trans_log_buf(args->trans, bp,
 	     XFS_DA_LOGRANGE(leaf, xfs_attr3_leaf_name(leaf, args->index),
@@ -2167,11 +2168,11 @@
 			if (!xfs_attr_namesp_match(args->flags, entry->flags))
 				continue;
 			args->index = probe;
-			args->valuelen = be32_to_cpu(name_rmt->valuelen);
+			args->rmtvaluelen = be32_to_cpu(name_rmt->valuelen);
 			args->rmtblkno = be32_to_cpu(name_rmt->valueblk);
 			args->rmtblkcnt = xfs_attr3_rmt_blocks(
 							args->dp->i_mount,
-							args->valuelen);
+							args->rmtvaluelen);
 			return XFS_ERROR(EEXIST);
 		}
 	}
@@ -2220,19 +2221,19 @@
 		name_rmt = xfs_attr3_leaf_name_remote(leaf, args->index);
 		ASSERT(name_rmt->namelen == args->namelen);
 		ASSERT(memcmp(args->name, name_rmt->name, args->namelen) == 0);
-		valuelen = be32_to_cpu(name_rmt->valuelen);
+		args->rmtvaluelen = be32_to_cpu(name_rmt->valuelen);
 		args->rmtblkno = be32_to_cpu(name_rmt->valueblk);
 		args->rmtblkcnt = xfs_attr3_rmt_blocks(args->dp->i_mount,
-						       valuelen);
+						       args->rmtvaluelen);
 		if (args->flags & ATTR_KERNOVAL) {
-			args->valuelen = valuelen;
+			args->valuelen = args->rmtvaluelen;
 			return 0;
 		}
-		if (args->valuelen < valuelen) {
-			args->valuelen = valuelen;
+		if (args->valuelen < args->rmtvaluelen) {
+			args->valuelen = args->rmtvaluelen;
 			return XFS_ERROR(ERANGE);
 		}
-		args->valuelen = valuelen;
+		args->valuelen = args->rmtvaluelen;
 	}
 	return 0;
 }
@@ -2519,7 +2520,7 @@
 		ASSERT((entry->flags & XFS_ATTR_LOCAL) == 0);
 		name_rmt = xfs_attr3_leaf_name_remote(leaf, args->index);
 		name_rmt->valueblk = cpu_to_be32(args->rmtblkno);
-		name_rmt->valuelen = cpu_to_be32(args->valuelen);
+		name_rmt->valuelen = cpu_to_be32(args->rmtvaluelen);
 		xfs_trans_log_buf(args->trans, bp,
 			 XFS_DA_LOGRANGE(leaf, name_rmt, sizeof(*name_rmt)));
 	}
@@ -2677,7 +2678,7 @@
 		ASSERT((entry1->flags & XFS_ATTR_LOCAL) == 0);
 		name_rmt = xfs_attr3_leaf_name_remote(leaf1, args->index);
 		name_rmt->valueblk = cpu_to_be32(args->rmtblkno);
-		name_rmt->valuelen = cpu_to_be32(args->valuelen);
+		name_rmt->valuelen = cpu_to_be32(args->rmtvaluelen);
 		xfs_trans_log_buf(args->trans, bp1,
 			 XFS_DA_LOGRANGE(leaf1, name_rmt, sizeof(*name_rmt)));
 	}
```
