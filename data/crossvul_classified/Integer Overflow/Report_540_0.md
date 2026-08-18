# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 540_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `540_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 691-734 of the vulnerable file.

	OPJ_UINT32 * lResolutionPtr;

	/* position in x and y of tile*/
	OPJ_UINT32 p, q;

	/* preconditions in debug*/
	assert(p_cp != 00);
	assert(p_image != 00);
	assert(tileno < p_cp->tw * p_cp->th);

	/* initializations*/
	tcp = &p_cp->tcps [tileno];
	l_tccp = tcp->tccps;
	l_img_comp = p_image->comps;

	/* position in x and y of tile*/
	p = tileno % p_cp->tw;
	q = tileno / p_cp->tw;

	/* here calculation of tx0, tx1, ty0, ty1, maxprec, l_dx and l_dy */
	*p_tx0 = opj_int_max((OPJ_INT32)(p_cp->tx0 + p * p_cp->tdx), (OPJ_INT32)p_image->x0);
	*p_tx1 = opj_int_min((OPJ_INT32)(p_cp->tx0 + (p + 1) * p_cp->tdx), (OPJ_INT32)p_image->x1);
	*p_ty0 = opj_int_max((OPJ_INT32)(p_cp->ty0 + q * p_cp->tdy), (OPJ_INT32)p_image->y0);
	*p_ty1 = opj_int_min((OPJ_INT32)(p_cp->ty0 + (q + 1) * p_cp->tdy), (OPJ_INT32)p_image->y1);

	/* max precision and resolution is 0 (can only grow)*/
	*p_max_prec = 0;
	*p_max_res = 0;

	/* take the largest value for dx_min and dy_min*/
	*p_dx_min = 0x7fffffff;
	*p_dy_min = 0x7fffffff;

	for (compno = 0; compno < p_image->numcomps; ++compno) {
		/* aritmetic variables to calculate*/
		OPJ_UINT32 l_level_no;
		OPJ_INT32 l_rx0, l_ry0, l_rx1, l_ry1;
		OPJ_INT32 l_px0, l_py0, l_px1, py1;
		OPJ_UINT32 l_product;
		OPJ_INT32 l_tcx0, l_tcy0, l_tcx1, l_tcy1;
		OPJ_UINT32 l_pdx, l_pdy , l_pw , l_ph;

		lResolutionPtr = p_resolutions[compno];

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -708,10 +708,10 @@
 	q = tileno / p_cp->tw;
 
 	/* here calculation of tx0, tx1, ty0, ty1, maxprec, l_dx and l_dy */
-	*p_tx0 = opj_int_max((OPJ_INT32)(p_cp->tx0 + p * p_cp->tdx), (OPJ_INT32)p_image->x0);
-	*p_tx1 = opj_int_min((OPJ_INT32)(p_cp->tx0 + (p + 1) * p_cp->tdx), (OPJ_INT32)p_image->x1);
-	*p_ty0 = opj_int_max((OPJ_INT32)(p_cp->ty0 + q * p_cp->tdy), (OPJ_INT32)p_image->y0);
-	*p_ty1 = opj_int_min((OPJ_INT32)(p_cp->ty0 + (q + 1) * p_cp->tdy), (OPJ_INT32)p_image->y1);
+	*p_tx0 = (OPJ_INT32)opj_uint_max(p_cp->tx0 + p * p_cp->tdx, p_image->x0);
+	*p_tx1 = (OPJ_INT32)opj_uint_min(p_cp->tx0 + (p + 1) * p_cp->tdx, p_image->x1);
+	*p_ty0 = (OPJ_INT32)opj_uint_max(p_cp->ty0 + q * p_cp->tdy, p_image->y0);
+	*p_ty1 = (OPJ_INT32)opj_uint_min(p_cp->ty0 + (q + 1) * p_cp->tdy, p_image->y1);
 
 	/* max precision and resolution is 0 (can only grow)*/
 	*p_max_prec = 0;
```
