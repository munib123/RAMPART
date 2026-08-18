# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5096_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5096_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 679-719 of the vulnerable file.

	OPJ_UINT32 l_nb_code_blocks_size;
	/* size of data for a tile */
	OPJ_UINT32 l_data_size;
	
	l_cp = p_tcd->cp;
	l_tcp = &(l_cp->tcps[p_tile_no]);
	l_tile = p_tcd->tcd_image->tiles;
	l_tccp = l_tcp->tccps;
	l_tilec = l_tile->comps;
	l_image = p_tcd->image;
	l_image_comp = p_tcd->image->comps;
	
	p = p_tile_no % l_cp->tw;       /* tile coordinates */
	q = p_tile_no / l_cp->tw;
	/*fprintf(stderr, "Tile coordinate = %d,%d\n", p, q);*/
	
	/* 4 borders of the tile rescale on the image if necessary */
	l_tx0 = l_cp->tx0 + p * l_cp->tdx; /* can't be greater than l_image->x1 so won't overflow */
	l_tile->x0 = (OPJ_INT32)opj_uint_max(l_tx0, l_image->x0);
	l_tile->x1 = (OPJ_INT32)opj_uint_min(opj_uint_adds(l_tx0, l_cp->tdx), l_image->x1);
	l_ty0 = l_cp->ty0 + q * l_cp->tdy; /* can't be greater than l_image->y1 so won't overflow */
	l_tile->y0 = (OPJ_INT32)opj_uint_max(l_ty0, l_image->y0);
	l_tile->y1 = (OPJ_INT32)opj_uint_min(opj_uint_adds(l_ty0, l_cp->tdy), l_image->y1);

	/* testcase 1888.pdf.asan.35.988 */
	if (l_tccp->numresolutions == 0) {
		opj_event_msg(manager, EVT_ERROR, "tiles require at least one resolution\n");
		return OPJ_FALSE;
	}
	/*fprintf(stderr, "Tile border = %d,%d,%d,%d\n", l_tile->x0, l_tile->y0,l_tile->x1,l_tile->y1);*/
	
	/*tile->numcomps = image->numcomps; */
	for (compno = 0; compno < l_tile->numcomps; ++compno) {
		/*fprintf(stderr, "compno = %d/%d\n", compno, l_tile->numcomps);*/
		l_image_comp->resno_decoded = 0;
		/* border of each l_tile component (global) */
		l_tilec->x0 = opj_int_ceildiv(l_tile->x0, (OPJ_INT32)l_image_comp->dx);
		l_tilec->y0 = opj_int_ceildiv(l_tile->y0, (OPJ_INT32)l_image_comp->dy);
		l_tilec->x1 = opj_int_ceildiv(l_tile->x1, (OPJ_INT32)l_image_comp->dx);
		l_tilec->y1 = opj_int_ceildiv(l_tile->y1, (OPJ_INT32)l_image_comp->dy);
		/*fprintf(stderr, "\tTile compo border = %d,%d,%d,%d\n", l_tilec->x0, l_tilec->y0,l_tilec->x1,l_tilec->y1);*/
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -696,9 +696,20 @@
 	l_tx0 = l_cp->tx0 + p * l_cp->tdx; /* can't be greater than l_image->x1 so won't overflow */
 	l_tile->x0 = (OPJ_INT32)opj_uint_max(l_tx0, l_image->x0);
 	l_tile->x1 = (OPJ_INT32)opj_uint_min(opj_uint_adds(l_tx0, l_cp->tdx), l_image->x1);
+	/* all those OPJ_UINT32 are casted to OPJ_INT32, let's do some sanity check */
+	if ((l_tile->x0 < 0) || (l_tile->x1 <= l_tile->x0)) {
+		opj_event_msg(manager, EVT_ERROR, "Tile X coordinates are not supported\n");
+		return OPJ_FALSE;
+	}
 	l_ty0 = l_cp->ty0 + q * l_cp->tdy; /* can't be greater than l_image->y1 so won't overflow */
 	l_tile->y0 = (OPJ_INT32)opj_uint_max(l_ty0, l_image->y0);
 	l_tile->y1 = (OPJ_INT32)opj_uint_min(opj_uint_adds(l_ty0, l_cp->tdy), l_image->y1);
+	/* all those OPJ_UINT32 are casted to OPJ_INT32, let's do some sanity check */
+	if ((l_tile->y0 < 0) || (l_tile->y1 <= l_tile->y0)) {
+		opj_event_msg(manager, EVT_ERROR, "Tile Y coordinates are not supported\n");
+		return OPJ_FALSE;
+	}
+	
 
 	/* testcase 1888.pdf.asan.35.988 */
 	if (l_tccp->numresolutions == 0) {
```
