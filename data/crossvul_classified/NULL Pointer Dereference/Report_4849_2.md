# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 4849_2
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4849_2`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 1821-1861 of the vulnerable file.

				t = jpc_fix_mul(t, absstepsize);
			} else {
				t = 0;
			}
			jas_matrix_set(x, i, j, t);
		}
	}

}

static void jpc_undo_roi(jas_matrix_t *x, int roishift, int bgshift, int numbps)
{
	int i;
	int j;
	int thresh;
	jpc_fix_t val;
	jpc_fix_t mag;
	bool warn;
	uint_fast32_t mask;

	if (roishift == 0 && bgshift == 0) {
		return;
	}
	thresh = 1 << roishift;

	warn = false;
	for (i = 0; i < jas_matrix_numrows(x); ++i) {
		for (j = 0; j < jas_matrix_numcols(x); ++j) {
			val = jas_matrix_get(x, i, j);
			mag = JAS_ABS(val);
			if (mag >= thresh) {
				/* We are dealing with ROI data. */
				mag >>= roishift;
				val = (val < 0) ? (-mag) : mag;
				jas_matrix_set(x, i, j, val);
			} else {
				/* We are dealing with non-ROI (i.e., background) data. */
				mag <<= bgshift;
				mask = (1 << numbps) - 1;
				/* Perform a basic sanity check on the sample value. */
				/* Some implementations write garbage in the unused
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1838,6 +1838,13 @@
 	bool warn;
 	uint_fast32_t mask;
 
+	if (roishift < 0) {
+		/* We could instead return an error here. */
+		/* I do not think it matters much. */
+		jas_eprintf("warning: forcing negative ROI shift to zero "
+		  "(bitstream is probably corrupt)\n");
+		roishift = 0;
+	}
 	if (roishift == 0 && bgshift == 0) {
 		return;
 	}
@@ -1856,7 +1863,7 @@
 			} else {
 				/* We are dealing with non-ROI (i.e., background) data. */
 				mag <<= bgshift;
-				mask = (1 << numbps) - 1;
+				mask = (JAS_CAST(uint_fast32_t, 1) << numbps) - 1;
 				/* Perform a basic sanity check on the sample value. */
 				/* Some implementations write garbage in the unused
 				  most-significant bit planes introduced by ROI shifting.
```
