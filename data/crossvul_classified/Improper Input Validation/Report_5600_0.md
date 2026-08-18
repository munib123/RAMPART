# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5600_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5600_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 470-510 of the vulnerable file.


/*
 *	Look up, and creates if absent, a lockable buffer for
 *	a given range of an inode.  The buffer is returned
 *	locked.	No I/O is implied by this call.
 */
xfs_buf_t *
_xfs_buf_find(
	struct xfs_buftarg	*btp,
	struct xfs_buf_map	*map,
	int			nmaps,
	xfs_buf_flags_t		flags,
	xfs_buf_t		*new_bp)
{
	size_t			numbytes;
	struct xfs_perag	*pag;
	struct rb_node		**rbp;
	struct rb_node		*parent;
	xfs_buf_t		*bp;
	xfs_daddr_t		blkno = map[0].bm_bn;
	int			numblks = 0;
	int			i;

	for (i = 0; i < nmaps; i++)
		numblks += map[i].bm_len;
	numbytes = BBTOB(numblks);

	/* Check for IOs smaller than the sector size / not sector aligned */
	ASSERT(!(numbytes < (1 << btp->bt_sshift)));
	ASSERT(!(BBTOB(blkno) & (xfs_off_t)btp->bt_smask));

	/* get tree root */
	pag = xfs_perag_get(btp->bt_mount,
				xfs_daddr_to_agno(btp->bt_mount, blkno));

	/* walk tree */
	spin_lock(&pag->pag_buf_lock);
	rbp = &pag->pag_buf_tree.rb_node;
	parent = NULL;
	bp = NULL;
	while (*rbp) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -487,6 +487,7 @@
 	struct rb_node		*parent;
 	xfs_buf_t		*bp;
 	xfs_daddr_t		blkno = map[0].bm_bn;
+	xfs_daddr_t		eofs;
 	int			numblks = 0;
 	int			i;
 
@@ -497,6 +498,23 @@
 	/* Check for IOs smaller than the sector size / not sector aligned */
 	ASSERT(!(numbytes < (1 << btp->bt_sshift)));
 	ASSERT(!(BBTOB(blkno) & (xfs_off_t)btp->bt_smask));
+
+	/*
+	 * Corrupted block numbers can get through to here, unfortunately, so we
+	 * have to check that the buffer falls within the filesystem bounds.
+	 */
+	eofs = XFS_FSB_TO_BB(btp->bt_mount, btp->bt_mount->m_sb.sb_dblocks);
+	if (blkno >= eofs) {
+		/*
+		 * XXX (dgc): we should really be returning EFSCORRUPTED here,
+		 * but none of the higher level infrastructure supports
+		 * returning a specific error on buffer lookup failures.
+		 */
+		xfs_alert(btp->bt_mount,
+			  "%s: Block out of range: block 0x%llx, EOFS 0x%llx ",
+			  __func__, blkno, eofs);
+		return NULL;
+	}
 
 	/* get tree root */
 	pag = xfs_perag_get(btp->bt_mount,
```
