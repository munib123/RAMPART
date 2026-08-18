# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 540_1
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `540_1`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 684-727 of the vulnerable file.

	/* number of code blocks for a precinct*/
	OPJ_UINT32 l_nb_code_blocks;
	/* room needed to store l_nb_code_blocks code blocks for a precinct*/
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
	l_tile->x0 = opj_int_max((OPJ_INT32)(l_cp->tx0 + p * l_cp->tdx), (OPJ_INT32)l_image->x0);
	l_tile->y0 = opj_int_max((OPJ_INT32)(l_cp->ty0 + q * l_cp->tdy), (OPJ_INT32)l_image->y0);
	l_tile->x1 = opj_int_min((OPJ_INT32)(l_cp->tx0 + (p + 1) * l_cp->tdx), (OPJ_INT32)l_image->x1);
	l_tile->y1 = opj_int_min((OPJ_INT32)(l_cp->ty0 + (q + 1) * l_cp->tdy), (OPJ_INT32)l_image->y1);
	/* testcase 1888.pdf.asan.35.988 */
	if (l_tccp->numresolutions == 0) {
		fprintf(stderr, "tiles require at least one resolution\n");
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
		
		/* compute l_data_size with overflow check */
		l_data_size = (OPJ_UINT32)(l_tilec->x1 - l_tilec->x0);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -701,10 +701,11 @@
 	/*fprintf(stderr, "Tile coordinate = %d,%d\n", p, q);*/
 	
 	/* 4 borders of the tile rescale on the image if necessary */
-	l_tile->x0 = opj_int_max((OPJ_INT32)(l_cp->tx0 + p * l_cp->tdx), (OPJ_INT32)l_image->x0);
-	l_tile->y0 = opj_int_max((OPJ_INT32)(l_cp->ty0 + q * l_cp->tdy), (OPJ_INT32)l_image->y0);
-	l_tile->x1 = opj_int_min((OPJ_INT32)(l_cp->tx0 + (p + 1) * l_cp->tdx), (OPJ_INT32)l_image->x1);
-	l_tile->y1 = opj_int_min((OPJ_INT32)(l_cp->ty0 + (q + 1) * l_cp->tdy), (OPJ_INT32)l_image->y1);
+	l_tile->x0 = (OPJ_INT32)opj_uint_max(l_cp->tx0 + p * l_cp->tdx, l_image->x0);
+	l_tile->y0 = (OPJ_INT32)opj_uint_max(l_cp->ty0 + q * l_cp->tdy, l_image->y0);
+	l_tile->x1 = (OPJ_INT32)opj_uint_min(l_cp->tx0 + (p + 1) * l_cp->tdx, l_image->x1);
+	l_tile->y1 = (OPJ_INT32)opj_uint_min(l_cp->ty0 + (q + 1) * l_cp->tdy, l_image->y1);
+
 	/* testcase 1888.pdf.asan.35.988 */
 	if (l_tccp->numresolutions == 0) {
 		fprintf(stderr, "tiles require at least one resolution\n");
```
