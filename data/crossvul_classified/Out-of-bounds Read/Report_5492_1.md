# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 5492_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5492_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 232-272 of the vulnerable file.

	jpc_picomp_t *picomp;
	int xstep;
	int ystep;
	uint_fast32_t r;
	uint_fast32_t rpx;
	uint_fast32_t rpy;
	uint_fast32_t trx0;
	uint_fast32_t try0;

	pchg = pi->pchg;
	if (!pi->prgvolfirst) {
		goto skip;
	} else {
		pi->xstep = 0;
		pi->ystep = 0;
		for (compno = 0, picomp = pi->picomps; compno < pi->numcomps;
		  ++compno, ++picomp) {
			for (rlvlno = 0, pirlvl = picomp->pirlvls; rlvlno <
			  picomp->numrlvls; ++rlvlno, ++pirlvl) {
				// Check for the potential for overflow problems.
				if (pirlvl->prcwidthexpn + pi->picomp->numrlvls >
				  JAS_UINTFAST32_NUMBITS - 2 ||
				  pirlvl->prcheightexpn + pi->picomp->numrlvls >
				  JAS_UINTFAST32_NUMBITS - 2) {
					return -1;
				}
				xstep = picomp->hsamp * (JAS_CAST(uint_fast32_t, 1) <<
				  (pirlvl->prcwidthexpn + picomp->numrlvls - rlvlno - 1));
				ystep = picomp->vsamp * (JAS_CAST(uint_fast32_t, 1) <<
				  (pirlvl->prcheightexpn + picomp->numrlvls - rlvlno - 1));
				pi->xstep = (!pi->xstep) ? xstep : JAS_MIN(pi->xstep, xstep);
				pi->ystep = (!pi->ystep) ? ystep : JAS_MIN(pi->ystep, ystep);
			}
		}
		pi->prgvolfirst = 0;
	}

	for (pi->rlvlno = pchg->rlvlnostart; pi->rlvlno < pchg->rlvlnoend &&
	  pi->rlvlno < pi->maxrlvls; ++pi->rlvlno) {
		for (pi->y = pi->ystart; pi->y < pi->yend; pi->y +=
		  pi->ystep - (pi->y % pi->ystep)) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -249,9 +249,9 @@
 			for (rlvlno = 0, pirlvl = picomp->pirlvls; rlvlno <
 			  picomp->numrlvls; ++rlvlno, ++pirlvl) {
 				// Check for the potential for overflow problems.
-				if (pirlvl->prcwidthexpn + pi->picomp->numrlvls >
+				if (pirlvl->prcwidthexpn + picomp->numrlvls >
 				  JAS_UINTFAST32_NUMBITS - 2 ||
-				  pirlvl->prcheightexpn + pi->picomp->numrlvls >
+				  pirlvl->prcheightexpn + picomp->numrlvls >
 				  JAS_UINTFAST32_NUMBITS - 2) {
 					return -1;
 				}
```
