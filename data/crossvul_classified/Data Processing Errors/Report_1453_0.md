# CrossVul Fix Pair: Data Processing Errors in c
**Pair ID:** 1453_0
**Vulnerability Class:** Data Processing Errors
**CWE:** CWE-19
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1453_0`)

## Vulnerability Information & PoC

## Description
Data Processing Errors

## Vulnerable Code
```c
Lines 196-236 of the vulnerable file.

	int			nblks;

	/*
	 * Determine space new attribute will use, and if it would be
	 * "local" or "remote" (note: local != inline).
	 */
	size = xfs_attr_leaf_newentsize(namelen, valuelen,
					mp->m_sb.sb_blocksize, local);

	nblks = XFS_DAENTER_SPACE_RES(mp, XFS_ATTR_FORK);
	if (*local) {
		if (size > (mp->m_sb.sb_blocksize >> 1)) {
			/* Double split possible */
			nblks *= 2;
		}
	} else {
		/*
		 * Out of line attribute, cannot double split, but
		 * make room for the attribute value itself.
		 */
		uint	dblocks = XFS_B_TO_FSB(mp, valuelen);
		nblks += dblocks;
		nblks += XFS_NEXTENTADD_SPACE_RES(mp, dblocks, XFS_ATTR_FORK);
	}

	return nblks;
}

STATIC int
xfs_attr_set_int(
	struct xfs_inode *dp,
	struct xfs_name	*name,
	unsigned char	*value,
	int		valuelen,
	int		flags)
{
	xfs_da_args_t		args;
	xfs_fsblock_t		firstblock;
	xfs_bmap_free_t		flist;
	int			error, err2, committed;
	struct xfs_mount	*mp = dp->i_mount;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -213,7 +213,7 @@
 		 * Out of line attribute, cannot double split, but
 		 * make room for the attribute value itself.
 		 */
-		uint	dblocks = XFS_B_TO_FSB(mp, valuelen);
+		uint	dblocks = xfs_attr3_rmt_blocks(mp, valuelen);
 		nblks += dblocks;
 		nblks += XFS_NEXTENTADD_SPACE_RES(mp, dblocks, XFS_ATTR_FORK);
 	}
@@ -698,11 +698,22 @@
 
 		trace_xfs_attr_leaf_replace(args);
 
+		/* save the attribute state for later removal*/
 		args->op_flags |= XFS_DA_OP_RENAME;	/* an atomic rename */
 		args->blkno2 = args->blkno;		/* set 2nd entry info*/
 		args->index2 = args->index;
 		args->rmtblkno2 = args->rmtblkno;
 		args->rmtblkcnt2 = args->rmtblkcnt;
+		args->rmtvaluelen2 = args->rmtvaluelen;
+
+		/*
+		 * clear the remote attr state now that it is saved so that the
+		 * values reflect the state of the attribute we are about to
+		 * add, not the attribute we just found and will remove later.
+		 */
+		args->rmtblkno = 0;
+		args->rmtblkcnt = 0;
+		args->rmtvaluelen = 0;
 	}
 
 	/*
@@ -794,6 +805,7 @@
 		args->blkno = args->blkno2;
 		args->rmtblkno = args->rmtblkno2;
 		args->rmtblkcnt = args->rmtblkcnt2;
+		args->rmtvaluelen = args->rmtvaluelen2;
 		if (args->rmtblkno) {
 			error = xfs_attr_rmtval_remove(args);
 			if (error)
@@ -999,13 +1011,22 @@
 
 		trace_xfs_attr_node_replace(args);
 
+		/* save the attribute state for later removal*/
 		args->op_flags |= XFS_DA_OP_RENAME;	/* atomic rename op */
 		args->blkno2 = args->blkno;		/* set 2nd entry info*/
 		args->index2 = args->index;
 		args->rmtblkno2 = args->rmtblkno;
 		args->rmtblkcnt2 = args->rmtblkcnt;
+		args->rmtvaluelen2 = args->rmtvaluelen;
+
+		/*
+		 * clear the remote attr state now that it is saved so that the
+		 * values reflect the state of the attribute we are about to
+		 * add, not the attribute we just found and will remove later.
+		 */
 		args->rmtblkno = 0;
 		args->rmtblkcnt = 0;
+		args->rmtvaluelen = 0;
 	}
 
 	retval = xfs_attr3_leaf_add(blk->bp, state->args);
@@ -1133,6 +1154,7 @@
 		args->blkno = args->blkno2;
 		args->rmtblkno = args->rmtblkno2;
 		args->rmtblkcnt = args->rmtblkcnt2;
+		args->rmtvaluelen = args->rmtvaluelen2;
 		if (args->rmtblkno) {
 			error = xfs_attr_rmtval_remove(args);
 			if (error)
```
