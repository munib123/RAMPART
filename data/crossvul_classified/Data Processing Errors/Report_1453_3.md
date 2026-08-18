# CrossVul Fix Pair: Data Processing Errors in c
**Pair ID:** 1453_3
**Vulnerability Class:** Data Processing Errors
**CWE:** CWE-19
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1453_3`)

## Vulnerability Information & PoC

## Description
Data Processing Errors

## Vulnerable Code
```c
Lines 320-360 of the vulnerable file.

		/* roll attribute data forwards */
		*valuelen -= byte_cnt;
		*src += byte_cnt;
		*offset += byte_cnt;
	}
}

/*
 * Read the value associated with an attribute from the out-of-line buffer
 * that we stored it in.
 */
int
xfs_attr_rmtval_get(
	struct xfs_da_args	*args)
{
	struct xfs_bmbt_irec	map[ATTR_RMTVALUE_MAPSIZE];
	struct xfs_mount	*mp = args->dp->i_mount;
	struct xfs_buf		*bp;
	xfs_dablk_t		lblkno = args->rmtblkno;
	__uint8_t		*dst = args->value;
	int			valuelen = args->valuelen;
	int			nmap;
	int			error;
	int			blkcnt = args->rmtblkcnt;
	int			i;
	int			offset = 0;

	trace_xfs_attr_rmtval_get(args);

	ASSERT(!(args->flags & ATTR_KERNOVAL));

	while (valuelen > 0) {
		nmap = ATTR_RMTVALUE_MAPSIZE;
		error = xfs_bmapi_read(args->dp, (xfs_fileoff_t)lblkno,
				       blkcnt, map, &nmap,
				       XFS_BMAPI_ATTRFORK);
		if (error)
			return error;
		ASSERT(nmap >= 1);

		for (i = 0; (i < nmap) && (valuelen > 0); i++) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -337,7 +337,7 @@
 	struct xfs_buf		*bp;
 	xfs_dablk_t		lblkno = args->rmtblkno;
 	__uint8_t		*dst = args->value;
-	int			valuelen = args->valuelen;
+	int			valuelen;
 	int			nmap;
 	int			error;
 	int			blkcnt = args->rmtblkcnt;
@@ -347,7 +347,9 @@
 	trace_xfs_attr_rmtval_get(args);
 
 	ASSERT(!(args->flags & ATTR_KERNOVAL));
-
+	ASSERT(args->rmtvaluelen == args->valuelen);
+
+	valuelen = args->rmtvaluelen;
 	while (valuelen > 0) {
 		nmap = ATTR_RMTVALUE_MAPSIZE;
 		error = xfs_bmapi_read(args->dp, (xfs_fileoff_t)lblkno,
@@ -415,7 +417,7 @@
 	 * attributes have headers, we can't just do a straight byte to FSB
 	 * conversion and have to take the header space into account.
 	 */
-	blkcnt = xfs_attr3_rmt_blocks(mp, args->valuelen);
+	blkcnt = xfs_attr3_rmt_blocks(mp, args->rmtvaluelen);
 	error = xfs_bmap_first_unused(args->trans, args->dp, blkcnt, &lfileoff,
 						   XFS_ATTR_FORK);
 	if (error)
@@ -480,7 +482,7 @@
 	 */
 	lblkno = args->rmtblkno;
 	blkcnt = args->rmtblkcnt;
-	valuelen = args->valuelen;
+	valuelen = args->rmtvaluelen;
 	while (valuelen > 0) {
 		struct xfs_buf	*bp;
 		xfs_daddr_t	dblkno;
```
