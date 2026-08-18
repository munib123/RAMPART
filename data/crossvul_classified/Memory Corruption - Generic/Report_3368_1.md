# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 3368_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3368_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 905-946 of the vulnerable file.

			else {
				ctx->intermediate32[((size_t)j)*ctx->intermed_canvas_width + i] = (iw_float32)out_pix[j];
			}
		}
	}

	retval=1;

done:
	if(rs && rs->disable_rrctx_cache && rs->rrctx) {
		// In some cases, the channels may need different resize contexts.
		// Delete the current context, so that it doesn't get reused.
		iwpvt_resize_rows_done(rs->rrctx);
		rs->rrctx = NULL;
	}
	if(inpix_tofree) iw_free(ctx,inpix_tofree);
	if(outpix_tofree) iw_free(ctx,outpix_tofree);
	return retval;
}

// 'handle_alpha_flag' must be set if an alpha channel exists and this is not
// the alpha channel.
static int iw_process_rows_intermediate_to_final(struct iw_context *ctx, int intermed_channel,
	const struct iw_csdescr *out_csdescr)
{
	int i,j;
	int z;
	int k;
	int retval=0;
	iw_tmpsample tmpsamp;
	iw_tmpsample alphasamp = 0.0;
	iw_tmpsample *inpix_tofree = NULL; // Used if we need a separate temp buffer for input samples
	iw_tmpsample *outpix_tofree = NULL; // Used if we need a separate temp buffer for output samples
	// Do any of the output channels use error-diffusion dithering?
	int using_errdiffdither = 0;
	int output_channel;
	int is_alpha_channel;
	int bkgd_has_transparency;
	double tmpbkgdalpha=0.0;
	int alt_bkgd = 0; // Nonzero if we should use bkgd2 for this sample
	struct iw_resize_settings *rs = NULL;
	int ditherfamily, dithersubtype;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -922,8 +922,6 @@
 	return retval;
 }
 
-// 'handle_alpha_flag' must be set if an alpha channel exists and this is not
-// the alpha channel.
 static int iw_process_rows_intermediate_to_final(struct iw_context *ctx, int intermed_channel,
 	const struct iw_csdescr *out_csdescr)
 {
@@ -951,13 +949,27 @@
 	iw_tmpsample *out_pix = NULL;
 	int num_in_pix;
 	int num_out_pix;
+	struct iw_channelinfo_out default_ci_out;
 
 	num_in_pix = ctx->intermed_canvas_width;
 	num_out_pix = ctx->img2.width;
 
 	int_ci = &ctx->intermed_ci[intermed_channel];
 	output_channel = int_ci->corresponding_output_channel;
-	out_ci = &ctx->img2_ci[output_channel];
+	if(output_channel>=0) {
+		out_ci = &ctx->img2_ci[output_channel];
+	}
+	else {
+		// If there is no output channelinfo struct, create a temporary one to
+		// use.
+		// TODO: This is admittedly ugly, but we use these settings for a few
+		// things even when there is no corresponding output channel, and I
+		// don't remember exactly why.
+		iw_zeromem(&default_ci_out, sizeof(struct iw_channelinfo_out));
+		default_ci_out.channeltype = IW_CHANNELTYPE_NONALPHA;
+		out_ci = &default_ci_out;
+	}
+
 	is_alpha_channel = (int_ci->channeltype==IW_CHANNELTYPE_ALPHA);
 	bkgd_has_transparency = iw_bkgd_has_transparency(ctx);
 
```
