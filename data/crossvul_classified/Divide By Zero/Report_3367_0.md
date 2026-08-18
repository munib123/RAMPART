# CrossVul Fix Pair: Divide By Zero in c
**Pair ID:** 3367_0
**Vulnerability Class:** Divide By Zero
**CWE:** CWE-369
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3367_0`)

## Vulnerability Information & PoC

## Description
Divide By Zero - This weakness typically occurs when an unexpected value is provided to the product, or if an error occurs that is not properly detected.

## Vulnerable Code
```c
Lines 466-506 of the vulnerable file.

{
	ctx->req.output_bkgd_label_valid = 1;
	ctx->req.output_bkgd_label = *clr;
}

IW_IMPL(void) iw_set_output_bkgd_label(struct iw_context *ctx, double r, double g, double b)
{
	struct iw_color clr;
	clr.c[0] = r;
	clr.c[1] = g;
	clr.c[2] = b;
	clr.c[3] = 1.0;
	iw_set_output_bkgd_label_2(ctx, &clr);
}

IW_IMPL(int) iw_get_input_density(struct iw_context *ctx,
   double *px, double *py, int *pcode)
{
	*px = 1.0;
	*py = 1.0;
	*pcode = ctx->img1.density_code;
	if(ctx->img1.density_code!=IW_DENSITY_UNKNOWN) {
		*px = ctx->img1.density_x;
		*py = ctx->img1.density_y;
		return 1;
	}
	return 0;
}

IW_IMPL(void) iw_set_output_density(struct iw_context *ctx,
   double x, double y, int code)
{
	ctx->img2.density_code = code;
	ctx->img2.density_x = x;
	ctx->img2.density_y = y;
}

// Detect a "gamma" colorspace that is actually linear.
static void optimize_csdescr(struct iw_csdescr *cs)
{
	if(cs->cstype!=IW_CSTYPE_GAMMA) return;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -483,13 +483,20 @@
 {
 	*px = 1.0;
 	*py = 1.0;
+	*pcode = IW_DENSITY_UNKNOWN;
+
+	if(ctx->img1.density_code==IW_DENSITY_UNKNOWN) {
+		return 0;
+	}
+	if(!iw_is_valid_density(ctx->img1.density_x, ctx->img1.density_y,
+		ctx->img1.density_code))
+	{
+		return 0;
+	}
+	*px = ctx->img1.density_x;
+	*py = ctx->img1.density_y;
 	*pcode = ctx->img1.density_code;
-	if(ctx->img1.density_code!=IW_DENSITY_UNKNOWN) {
-		*px = ctx->img1.density_x;
-		*py = ctx->img1.density_y;
-		return 1;
-	}
-	return 0;
+	return 1;
 }
 
 IW_IMPL(void) iw_set_output_density(struct iw_context *ctx,
```
