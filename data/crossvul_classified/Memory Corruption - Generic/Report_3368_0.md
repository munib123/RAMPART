# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 3368_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3368_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 830-870 of the vulnerable file.

	oldbpr = img->bpr;
	img->bpr = iw_calc_bytesperrow(img->width,24);

	for(j=0;j<img->height;j++) {
		for(i=0;i<img->width;i++) {
			img->pixels[j*img->bpr + i*3 + 0] = img->pixels[j*oldbpr + i*4 + 0];
			img->pixels[j*img->bpr + i*3 + 1] = img->pixels[j*oldbpr + i*4 + 1];
			img->pixels[j*img->bpr + i*3 + 2] = img->pixels[j*oldbpr + i*4 + 2];
		}
	}
}

static int bmpr_read_rle(struct iwbmprcontext *rctx)
{
	int retval = 0;

	if(!(rctx->compression==IWBMP_BI_RLE8 && rctx->bitcount==8) &&
		!(rctx->compression==IWBMP_BI_RLE4 && rctx->bitcount==4))
	{
		iw_set_error(rctx->ctx,"Compression type incompatible with image type");
	}

	if(rctx->topdown) {
		// The documentation says that top-down images may not be compressed.
		iw_set_error(rctx->ctx,"Compression not allowed with top-down images");
	}

	// RLE-compressed BMP images don't have to assign a color to every pixel,
	// and it's reasonable to interpret undefined pixels as transparent.
	// I'm not going to worry about handling compressed BMP images as
	// efficiently as possible, so start with an RGBA image, and convert to
	// RGB format later if (as is almost always the case) there was no
	// transparency.
	rctx->img->imgtype = IW_IMGTYPE_RGBA;
	rctx->img->bit_depth = 8;
	rctx->img->bpr = iw_calc_bytesperrow(rctx->width,32);

	rctx->img->pixels = (iw_byte*)iw_malloc_large(rctx->ctx,rctx->img->bpr,rctx->img->height);
	if(!rctx->img->pixels) goto done;

	if(!bmpr_read_rle_internal(rctx)) goto done;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -847,11 +847,13 @@
 		!(rctx->compression==IWBMP_BI_RLE4 && rctx->bitcount==4))
 	{
 		iw_set_error(rctx->ctx,"Compression type incompatible with image type");
+		goto done;
 	}
 
 	if(rctx->topdown) {
 		// The documentation says that top-down images may not be compressed.
 		iw_set_error(rctx->ctx,"Compression not allowed with top-down images");
+		goto done;
 	}
 
 	// RLE-compressed BMP images don't have to assign a color to every pixel,
```
