# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 5352_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5352_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 47-87 of the vulnerable file.

	int assign_rp = 0;
	mpi_size_t tsize = 0;	/* to avoid compiler warning */
	/* fixme: we should check that the warning is void */
	int rc = -ENOMEM;

	esize = exp->nlimbs;
	msize = mod->nlimbs;
	size = 2 * msize;
	esign = exp->sign;
	msign = mod->sign;

	rp = res->d;
	ep = exp->d;

	if (!msize)
		return -EINVAL;

	if (!esize) {
		/* Exponent is zero, result is 1 mod MOD, i.e., 1 or 0
		 * depending on if MOD equals 1.  */
		rp[0] = 1;
		res->nlimbs = (msize == 1 && mod->d[0] == 1) ? 0 : 1;
		res->sign = 0;
		goto leave;
	}

	/* Normalize MOD (i.e. make its most significant bit set) as required by
	 * mpn_divrem.  This will make the intermediate values in the calculation
	 * slightly larger, but the correct result is obtained after a final
	 * reduction using the original MOD value.  */
	mp = mp_marker = mpi_alloc_limb_space(msize);
	if (!mp)
		goto enomem;
	mod_shift_cnt = count_leading_zeros(mod->d[msize - 1]);
	if (mod_shift_cnt)
		mpihelp_lshift(mp, mod->d, msize, mod_shift_cnt);
	else
		MPN_COPY(mp, mod->d, msize);

	bsize = base->nlimbs;
	bsign = base->sign;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -64,8 +64,13 @@
 	if (!esize) {
 		/* Exponent is zero, result is 1 mod MOD, i.e., 1 or 0
 		 * depending on if MOD equals 1.  */
-		rp[0] = 1;
 		res->nlimbs = (msize == 1 && mod->d[0] == 1) ? 0 : 1;
+		if (res->nlimbs) {
+			if (mpi_resize(res, 1) < 0)
+				goto enomem;
+			rp = res->d;
+			rp[0] = 1;
+		}
 		res->sign = 0;
 		goto leave;
 	}
```
