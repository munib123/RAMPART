# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 4852_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4852_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 415-458 of the vulnerable file.

	int prchind;
	int prcvind;
	int *prclyrno;
	uint_fast32_t trx0;
	uint_fast32_t try0;
	uint_fast32_t r;
	uint_fast32_t rpx;
	uint_fast32_t rpy;

	pchg = pi->pchg;
	if (!pi->prgvolfirst) {
		goto skip;
	} else {
		pi->prgvolfirst = 0;
	}

	for (pi->compno = pchg->compnostart, pi->picomp =
	  &pi->picomps[pi->compno]; pi->compno < JAS_CAST(int, pchg->compnoend) && pi->compno < pi->numcomps; ++pi->compno,
	  ++pi->picomp) {
		pirlvl = pi->picomp->pirlvls;
		pi->xstep = pi->picomp->hsamp * (1 << (pirlvl->prcwidthexpn +
		  pi->picomp->numrlvls - 1));
		pi->ystep = pi->picomp->vsamp * (1 << (pirlvl->prcheightexpn +
		  pi->picomp->numrlvls - 1));
		for (rlvlno = 1, pirlvl = &pi->picomp->pirlvls[1];
		  rlvlno < pi->picomp->numrlvls; ++rlvlno, ++pirlvl) {
			pi->xstep = JAS_MIN(pi->xstep, pi->picomp->hsamp * (1 <<
			  (pirlvl->prcwidthexpn + pi->picomp->numrlvls -
			  rlvlno - 1)));
			pi->ystep = JAS_MIN(pi->ystep, pi->picomp->vsamp * (1 <<
			  (pirlvl->prcheightexpn + pi->picomp->numrlvls -
			  rlvlno - 1)));
		}
		for (pi->y = pi->ystart; pi->y < pi->yend;
		  pi->y += pi->ystep - (pi->y % pi->ystep)) {
			for (pi->x = pi->xstart; pi->x < pi->xend;
			  pi->x += pi->xstep - (pi->x % pi->xstep)) {
				for (pi->rlvlno = pchg->rlvlnostart,
				  pi->pirlvl = &pi->picomp->pirlvls[pi->rlvlno];
				  pi->rlvlno < pi->picomp->numrlvls && pi->rlvlno <
				  pchg->rlvlnoend; ++pi->rlvlno, ++pi->pirlvl) {
					if (pi->pirlvl->numprcs == 0) {
						continue;
					}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -432,18 +432,18 @@
 	  &pi->picomps[pi->compno]; pi->compno < JAS_CAST(int, pchg->compnoend) && pi->compno < pi->numcomps; ++pi->compno,
 	  ++pi->picomp) {
 		pirlvl = pi->picomp->pirlvls;
-		pi->xstep = pi->picomp->hsamp * (1 << (pirlvl->prcwidthexpn +
-		  pi->picomp->numrlvls - 1));
-		pi->ystep = pi->picomp->vsamp * (1 << (pirlvl->prcheightexpn +
-		  pi->picomp->numrlvls - 1));
+		pi->xstep = pi->picomp->hsamp * (JAS_CAST(uint_fast32_t, 1) <<
+		  (pirlvl->prcwidthexpn + pi->picomp->numrlvls - 1));
+		pi->ystep = pi->picomp->vsamp * (JAS_CAST(uint_fast32_t, 1) <<
+		  (pirlvl->prcheightexpn + pi->picomp->numrlvls - 1));
 		for (rlvlno = 1, pirlvl = &pi->picomp->pirlvls[1];
 		  rlvlno < pi->picomp->numrlvls; ++rlvlno, ++pirlvl) {
-			pi->xstep = JAS_MIN(pi->xstep, pi->picomp->hsamp * (1 <<
-			  (pirlvl->prcwidthexpn + pi->picomp->numrlvls -
-			  rlvlno - 1)));
-			pi->ystep = JAS_MIN(pi->ystep, pi->picomp->vsamp * (1 <<
-			  (pirlvl->prcheightexpn + pi->picomp->numrlvls -
-			  rlvlno - 1)));
+			pi->xstep = JAS_MIN(pi->xstep, pi->picomp->hsamp *
+			  (JAS_CAST(uint_fast32_t, 1) << (pirlvl->prcwidthexpn +
+			  pi->picomp->numrlvls - rlvlno - 1)));
+			pi->ystep = JAS_MIN(pi->ystep, pi->picomp->vsamp *
+			  (JAS_CAST(uint_fast32_t, 1) << (pirlvl->prcheightexpn +
+			  pi->picomp->numrlvls - rlvlno - 1)));
 		}
 		for (pi->y = pi->ystart; pi->y < pi->yend;
 		  pi->y += pi->ystep - (pi->y % pi->ystep)) {
```
