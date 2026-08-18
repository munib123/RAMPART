# CrossVul Fix Pair: Divide By Zero in c
**Pair ID:** 3308_0
**Vulnerability Class:** Divide By Zero
**CWE:** CWE-369
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3308_0`)

## Vulnerability Information & PoC

## Description
Divide By Zero - This weakness typically occurs when an unexpected value is provided to the product, or if an error occurs that is not properly detected.

## Vulnerable Code
```c
Lines 597-637 of the vulnerable file.


static int iwgif_read_image(struct iwgifrcontext *rctx)
{
	int retval=0;
	struct lzwdeccontext d;
	size_t subblocksize;
	int has_local_ct;
	int local_ct_size;

	unsigned int root_codesize;

	// Read image header information
	if(!iwgif_read(rctx,rctx->rbuf,9)) goto done;

	rctx->image_left = (int)iw_get_ui16le(&rctx->rbuf[0]);
	rctx->image_top = (int)iw_get_ui16le(&rctx->rbuf[2]);
	// image_left and _top may be updated in iwgif_init_screen().

	rctx->image_width = (int)iw_get_ui16le(&rctx->rbuf[4]);
	rctx->image_height = (int)iw_get_ui16le(&rctx->rbuf[6]);

	rctx->interlaced = (int)((rctx->rbuf[8]>>6)&0x01);

	has_local_ct = (int)((rctx->rbuf[8]>>7)&0x01);
	if(has_local_ct) {
		local_ct_size = (int)(rctx->rbuf[8]&0x07);
		rctx->colortable.num_entries = 1<<(1+local_ct_size);
	}

	if(has_local_ct) {
		// We only support one image, so we don't need to keep both a global and a
		// local color table. If an image has both, the local table will overwrite
		// the global one.
		if(!iwgif_read_color_table(rctx,&rctx->colortable)) goto done;
	}

	// Make the transparent color transparent.
	if(rctx->has_transparency) {
	    rctx->colortable.entry[rctx->trans_color_index].a = 0;
	}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -614,6 +614,10 @@
 
 	rctx->image_width = (int)iw_get_ui16le(&rctx->rbuf[4]);
 	rctx->image_height = (int)iw_get_ui16le(&rctx->rbuf[6]);
+	if(rctx->image_width<1 || rctx->image_height<1) {
+		iw_set_error(rctx->ctx, "Invalid image dimensions");
+		goto done;
+	}
 
 	rctx->interlaced = (int)((rctx->rbuf[8]>>6)&0x01);
 
```
