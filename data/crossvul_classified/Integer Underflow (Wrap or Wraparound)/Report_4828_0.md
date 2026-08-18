# CrossVul Fix Pair: Integer Underflow (Wrap or Wraparound) in c
**Pair ID:** 4828_0
**Vulnerability Class:** Integer Underflow (Wrap or Wraparound)
**CWE:** CWE-191
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4828_0`)

## Vulnerability Information & PoC

## Description
Integer Underflow (Wrap or Wraparound) - This can happen in signed and unsigned cases.

## Vulnerable Code
```c
Lines 812-852 of the vulnerable file.

				new_r += kernel * gdTrueColorGetRed(rgbs);
				new_g += kernel * gdTrueColorGetGreen(rgbs);
				new_b += kernel * gdTrueColorGetBlue(rgbs);
				new_a += kernel * gdTrueColorGetAlpha(rgbs);
			}
		}
	}

	new_r = CLAMP(new_r, 0, 255);
	new_g = CLAMP(new_g, 0, 255);
	new_b = CLAMP(new_b, 0, 255);
	new_a = CLAMP(new_a, 0, gdAlphaMax);

	return gdTrueColorAlpha(((int)new_r), ((int)new_g), ((int)new_b), ((int)new_a));
}

static inline LineContribType * _gdContributionsAlloc(unsigned int line_length, unsigned int windows_size)
{
	unsigned int u = 0;
	LineContribType *res;
	int overflow_error = 0;

	res = (LineContribType *) gdMalloc(sizeof(LineContribType));
	if (!res) {
		return NULL;
	}
	res->WindowSize = windows_size;
	res->LineLength = line_length;
	if (overflow2(line_length, sizeof(ContributionType))) {
		gdFree(res);
		return NULL;
	}
	res->ContribRow = (ContributionType *) gdMalloc(line_length * sizeof(ContributionType));
	if (res->ContribRow == NULL) {
		gdFree(res);
		return NULL;
	}
	for (u = 0 ; u < line_length ; u++) {
		if (overflow2(windows_size, sizeof(double))) {
			overflow_error = 1;
		} else {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -829,8 +829,13 @@
 {
 	unsigned int u = 0;
 	LineContribType *res;
-	int overflow_error = 0;
-
+	size_t weights_size;
+
+	if (overflow2(windows_size, sizeof(double))) {
+		return NULL;
+	} else {
+		weights_size = windows_size * sizeof(double);
+	}
 	res = (LineContribType *) gdMalloc(sizeof(LineContribType));
 	if (!res) {
 		return NULL;
@@ -847,15 +852,11 @@
 		return NULL;
 	}
 	for (u = 0 ; u < line_length ; u++) {
-		if (overflow2(windows_size, sizeof(double))) {
-			overflow_error = 1;
-		} else {
-			res->ContribRow[u].Weights = (double *) gdMalloc(windows_size * sizeof(double));
-		}
-		if (overflow_error == 1 || res->ContribRow[u].Weights == NULL) {
+		res->ContribRow[u].Weights = (double *) gdMalloc(weights_size);
+		if (res->ContribRow[u].Weights == NULL) {
 			unsigned int i;
-			u--;
-			for (i=0;i<=u;i++) {
+
+			for (i=0;i<u;i++) {
 				gdFree(res->ContribRow[i].Weights);
 			}
 			gdFree(res->ContribRow);
```
