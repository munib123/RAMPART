# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 5869_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5869_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 936-978 of the vulnerable file.

	LineContribType *res;

	if (scale_d < 1.0) {
		width_d = filter_width_d / scale_d;
		scale_f_d = scale_d;
	}  else {
		width_d= filter_width_d;
	}

	windows_size = 2 * (int)ceil(width_d) + 1;
	res = _gdContributionsAlloc(line_size, windows_size);

	for (u = 0; u < line_size; u++) {
		const double dCenter = (double)u / scale_d;
		/* get the significant edge points affecting the pixel */
		register int iLeft = MAX(0, (int)floor (dCenter - width_d));
		int iRight = MIN((int)ceil(dCenter + width_d), (int)src_size - 1);
		double dTotalWeight = 0.0;
		int iSrc;

		res->ContribRow[u].Left = iLeft;
		res->ContribRow[u].Right = iRight;

		/* Cut edge points to fit in filter window in case of spill-off */
		if (iRight - iLeft + 1 > windows_size)  {
			if (iLeft < ((int)src_size - 1 / 2))  {
				iLeft++;
			} else {
				iRight--;
			}
		}

		for (iSrc = iLeft; iSrc <= iRight; iSrc++) {
			dTotalWeight += (res->ContribRow[u].Weights[iSrc-iLeft] =  scale_f_d * (*pFilter)(scale_f_d * (dCenter - (double)iSrc)));
		}

		if (dTotalWeight < 0.0) {
			_gdContributionsFree(res);
			return NULL;
		}

		if (dTotalWeight > 0.0) {
			for (iSrc = iLeft; iSrc <= iRight; iSrc++) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -953,9 +953,6 @@
 		double dTotalWeight = 0.0;
 		int iSrc;
 
-		res->ContribRow[u].Left = iLeft;
-		res->ContribRow[u].Right = iRight;
-
 		/* Cut edge points to fit in filter window in case of spill-off */
 		if (iRight - iLeft + 1 > windows_size)  {
 			if (iLeft < ((int)src_size - 1 / 2))  {
@@ -964,6 +961,9 @@
 				iRight--;
 			}
 		}
+
+		res->ContribRow[u].Left = iLeft;
+		res->ContribRow[u].Right = iRight;
 
 		for (iSrc = iLeft; iSrc <= iRight; iSrc++) {
 			dTotalWeight += (res->ContribRow[u].Weights[iSrc-iLeft] =  scale_f_d * (*pFilter)(scale_f_d * (dCenter - (double)iSrc)));
```
