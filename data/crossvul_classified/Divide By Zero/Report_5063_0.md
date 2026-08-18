# CrossVul Fix Pair: Divide By Zero in c
**Pair ID:** 5063_0
**Vulnerability Class:** Divide By Zero
**CWE:** CWE-369
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5063_0`)

## Vulnerability Information & PoC

## Description
Divide By Zero - This weakness typically occurs when an unexpected value is provided to the product, or if an error occurs that is not properly detected.

## Vulnerable Code
```c
Lines 703-743 of the vulnerable file.

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
		
		/* compute l_data_size with overflow check */
		l_data_size = (OPJ_UINT32)(l_tilec->x1 - l_tilec->x0);
		if ((((OPJ_UINT32)-1) / l_data_size) < (OPJ_UINT32)(l_tilec->y1 - l_tilec->y0)) {
			opj_event_msg(manager, EVT_ERROR, "Not enough memory for tile data\n");
			return OPJ_FALSE;
		}
		l_data_size = l_data_size * (OPJ_UINT32)(l_tilec->y1 - l_tilec->y0);
		
		if ((((OPJ_UINT32)-1) / (OPJ_UINT32)sizeof(OPJ_UINT32)) < l_data_size) {
			opj_event_msg(manager, EVT_ERROR, "Not enough memory for tile data\n");
			return OPJ_FALSE;
		}
		l_data_size = l_data_size * (OPJ_UINT32)sizeof(OPJ_UINT32);
		l_tilec->numresolutions = l_tccp->numresolutions;
		if (l_tccp->numresolutions < l_cp->m_specific_param.m_dec.m_reduce) {
			l_tilec->minimum_num_resolutions = 1;
		}
		else {
			l_tilec->minimum_num_resolutions = l_tccp->numresolutions - l_cp->m_specific_param.m_dec.m_reduce;
		}
		
		l_tilec->data_size_needed = l_data_size;
		if (p_tcd->m_is_decoder && !opj_alloc_tile_component_data(l_tilec)) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -720,7 +720,8 @@
 		
 		/* compute l_data_size with overflow check */
 		l_data_size = (OPJ_UINT32)(l_tilec->x1 - l_tilec->x0);
-		if ((((OPJ_UINT32)-1) / l_data_size) < (OPJ_UINT32)(l_tilec->y1 - l_tilec->y0)) {
+		/* issue 733, l_data_size == 0U, probably something wrong should be checked before getting here */
+		if ((l_data_size > 0U) && ((((OPJ_UINT32)-1) / l_data_size) < (OPJ_UINT32)(l_tilec->y1 - l_tilec->y0))) {
 			opj_event_msg(manager, EVT_ERROR, "Not enough memory for tile data\n");
 			return OPJ_FALSE;
 		}
```
