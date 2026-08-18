# CrossVul Fix Pair: Incorrect Calculation in c
**Pair ID:** 3331_0
**Vulnerability Class:** Incorrect Calculation
**CWE:** CWE-682
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3331_0`)

## Vulnerability Information & PoC

## Description
Incorrect Calculation - When product performs a security-critical calculation incorrectly, it might lead to incorrect resource allocations, incorrect privilege assignments, or failed comparisons among other things.

## Vulnerable Code
```c
Lines 408-448 of the vulnerable file.

	else {
		iw_set_error(rctx->ctx,"Unsupported BMP version");
		goto done;
	}

	if(!iw_check_image_dimensions(rctx->ctx,rctx->width,rctx->height)) {
		goto done;
	}

	retval = 1;

done:
	return retval;
}

// Find the highest/lowest bit that is set.
static int find_high_bit(unsigned int x)
{
	int i;
	for(i=31;i>=0;i--) {
		if(x&(1<<i)) return i;
	}
	return 0;
}
static int find_low_bit(unsigned int x)
{
	int i;
	for(i=0;i<=31;i++) {
		if(x&(1<<i)) return i;
	}
	return 0;
}

// Given .bf_mask[k], set high_bit[k], low_bit[k], etc.
static int process_bf_mask(struct iwbmprcontext *rctx, int k)
{
	// The bits representing the mask for each channel are required to be
	// contiguous, so all we need to do is find the highest and lowest bit.
	rctx->bf_high_bit[k] = find_high_bit(rctx->bf_mask[k]);
	rctx->bf_low_bit[k] = find_low_bit(rctx->bf_mask[k]);
	rctx->bf_bits_count[k] = 1+rctx->bf_high_bit[k]-rctx->bf_low_bit[k];
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -425,7 +425,7 @@
 {
 	int i;
 	for(i=31;i>=0;i--) {
-		if(x&(1<<i)) return i;
+		if(x&(1U<<(unsigned int)i)) return i;
 	}
 	return 0;
 }
@@ -433,7 +433,7 @@
 {
 	int i;
 	for(i=0;i<=31;i++) {
-		if(x&(1<<i)) return i;
+		if(x&(1U<<(unsigned int)i)) return i;
 	}
 	return 0;
 }
```
