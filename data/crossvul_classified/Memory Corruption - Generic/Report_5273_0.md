# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 5273_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5273_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 1224-1264 of the vulnerable file.

		l_tmp_ptr[compno] = l_encoding_value_ptr;
		l_encoding_value_ptr += l_data_stride;
	}
	/* get encoding parameters */
	opj_get_all_encoding_parameters(p_image,p_cp,p_tile_no,&l_tx0,&l_tx1,&l_ty0,&l_ty1,&l_dx_min,&l_dy_min,&l_max_prec,&l_max_res,l_tmp_ptr);

	/* step calculations */
	l_step_p = 1;
	l_step_c = l_max_prec * l_step_p;
	l_step_r = p_image->numcomps * l_step_c;
	l_step_l = l_max_res * l_step_r;

	/* set values for first packet iterator */
	l_current_pi = l_pi;

	/* memory allocation for include */
	/* prevent an integer overflow issue */
	l_current_pi->include = 00;
	if (l_step_l <= (SIZE_MAX / (l_tcp->numlayers + 1U)))
	{
		l_current_pi->include = (OPJ_INT16*) opj_calloc((l_tcp->numlayers +1) * l_step_l, sizeof(OPJ_INT16));
	}

	if
		(!l_current_pi->include)
	{
		opj_free(l_tmp_data);
		opj_free(l_tmp_ptr);
		opj_pi_destroy(l_pi, l_bound);
		return 00;
	}

	/* special treatment for the first packet iterator */
	l_current_comp = l_current_pi->comps;
	l_img_comp = p_image->comps;
	l_tccp = l_tcp->tccps;

	l_current_pi->tx0 = l_tx0;
	l_current_pi->ty0 = l_ty0;
	l_current_pi->tx1 = l_tx1;
	l_current_pi->ty1 = l_ty1;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1241,7 +1241,7 @@
 	l_current_pi->include = 00;
 	if (l_step_l <= (SIZE_MAX / (l_tcp->numlayers + 1U)))
 	{
-		l_current_pi->include = (OPJ_INT16*) opj_calloc((l_tcp->numlayers +1) * l_step_l, sizeof(OPJ_INT16));
+		l_current_pi->include = (OPJ_INT16*) opj_calloc((size_t)(l_tcp->numlayers + 1U) * l_step_l, sizeof(OPJ_INT16));
 	}
 
 	if
```
