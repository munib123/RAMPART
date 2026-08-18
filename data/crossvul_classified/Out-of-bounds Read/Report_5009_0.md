# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 5009_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5009_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 74-114 of the vulnerable file.

static void sycc_to_rgb(int offset, int upb, int y, int cb, int cr,
	int *out_r, int *out_g, int *out_b)
{
	int r, g, b;

	cb -= offset; cr -= offset;
	r = y + (int)(1.402 * (float)cr);
	if(r < 0) r = 0; else if(r > upb) r = upb; *out_r = r;

	g = y - (int)(0.344 * (float)cb + 0.714 * (float)cr);
	if(g < 0) g = 0; else if(g > upb) g = upb; *out_g = g;

	b = y + (int)(1.772 * (float)cb);
	if(b < 0) b = 0; else if(b > upb) b = upb; *out_b = b;
}

static void sycc444_to_rgb(opj_image_t *img)
{
	int *d0, *d1, *d2, *r, *g, *b;
	const int *y, *cb, *cr;
	unsigned int maxw, maxh, max, i;
	int offset, upb;

	upb = (int)img->comps[0].prec;
	offset = 1<<(upb - 1); upb = (1<<upb)-1;

	maxw = (unsigned int)img->comps[0].w; maxh = (unsigned int)img->comps[0].h;
	max = maxw * maxh;

	y = img->comps[0].data;
	cb = img->comps[1].data;
	cr = img->comps[2].data;

	d0 = r = (int*)malloc(sizeof(int) * (size_t)max);
	d1 = g = (int*)malloc(sizeof(int) * (size_t)max);
	d2 = b = (int*)malloc(sizeof(int) * (size_t)max);

	if(r == NULL || g == NULL || b == NULL) goto fails;

	for(i = 0U; i < max; ++i)
	{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -91,22 +91,22 @@
 {
 	int *d0, *d1, *d2, *r, *g, *b;
 	const int *y, *cb, *cr;
-	unsigned int maxw, maxh, max, i;
+	size_t maxw, maxh, max, i;
 	int offset, upb;
 
 	upb = (int)img->comps[0].prec;
 	offset = 1<<(upb - 1); upb = (1<<upb)-1;
 
-	maxw = (unsigned int)img->comps[0].w; maxh = (unsigned int)img->comps[0].h;
+	maxw = (size_t)img->comps[0].w; maxh = (size_t)img->comps[0].h;
 	max = maxw * maxh;
 
 	y = img->comps[0].data;
 	cb = img->comps[1].data;
 	cr = img->comps[2].data;
 
-	d0 = r = (int*)malloc(sizeof(int) * (size_t)max);
-	d1 = g = (int*)malloc(sizeof(int) * (size_t)max);
-	d2 = b = (int*)malloc(sizeof(int) * (size_t)max);
+	d0 = r = (int*)malloc(sizeof(int) * max);
+	d1 = g = (int*)malloc(sizeof(int) * max);
+	d2 = b = (int*)malloc(sizeof(int) * max);
 
 	if(r == NULL || g == NULL || b == NULL) goto fails;
 
@@ -118,107 +118,138 @@
 	free(img->comps[0].data); img->comps[0].data = d0;
 	free(img->comps[1].data); img->comps[1].data = d1;
 	free(img->comps[2].data); img->comps[2].data = d2;
+	img->color_space = OPJ_CLRSPC_SRGB;
 	return;
 
 fails:
-	if(r) free(r);
-	if(g) free(g);
-	if(b) free(b);
-
+	free(r);
+	free(g);
+	free(b);
 }/* sycc444_to_rgb() */
 
 static void sycc422_to_rgb(opj_image_t *img)
 {	
 	int *d0, *d1, *d2, *r, *g, *b;
 	const int *y, *cb, *cr;
-	unsigned int maxw, maxh, max;
+	size_t maxw, maxh, max, offx, loopmaxw;
 	int offset, upb;
-	unsigned int i, j;
+	size_t i;
 
 	upb = (int)img->comps[0].prec;
 	offset = 1<<(upb - 1); upb = (1<<upb)-1;
 
-	maxw = (unsigned int)img->comps[0].w; maxh = (unsigned int)img->comps[0].h;
+	maxw = (size_t)img->comps[0].w; maxh = (size_t)img->comps[0].h;
 	max = maxw * maxh;
 
 	y = img->comps[0].data;
 	cb = img->comps[1].data;
 	cr = img->comps[2].data;
 
-	d0 = r = (int*)malloc(sizeof(int) * (size_t)max);
-	d1 = g = (int*)malloc(sizeof(int) * (size_t)max);
-	d2 = b = (int*)malloc(sizeof(int) * (size_t)max);
+	d0 = r = (int*)malloc(sizeof(int) * max);
+	d1 = g = (int*)malloc(sizeof(int) * max);
+	d2 = b = (int*)malloc(sizeof(int) * max);
 
 	if(r == NULL || g == NULL || b == NULL) goto fails;
 
+	/* if img->x0 is odd, then first column shall use Cb/Cr = 0 */
+	offx = img->x0 & 1U;
+	loopmaxw = maxw - offx;
+	
 	for(i=0U; i < maxh; ++i)
 	{
-		for(j=0U; j < (maxw & ~(unsigned int)1U); j += 2U)
+		size_t j;
+		
+		if (offx > 0U) {
+			sycc_to_rgb(offset, upb, *y, 0, 0, r, g, b);
+			++y; ++r; ++g; ++b;
+		}
+		
+		for(j=0U; j < (loopmaxw & ~(size_t)1U); j += 2U)
 		{
 			sycc_to_rgb(offset, upb, *y, *cb, *cr, r, g, b);
 			++y; ++r; ++g; ++b;
 			sycc_to_rgb(offset, upb, *y, *cb, *cr, r, g, b);
 			++y; ++r; ++g; ++b; ++cb; ++cr;
 		}
-		if (j < maxw) {
+		if (j < loopmaxw) {
 			sycc_to_rgb(offset, upb, *y, *cb, *cr, r, g, b);
 			++y; ++r; ++g; ++b; ++cb; ++cr;
 		}
 	}
+	
 	free(img->comps[0].data); img->comps[0].data = d0;
 	free(img->comps[1].data); img->comps[1].data = d1;
 	free(img->comps[2].data); img->comps[2].data = d2;
 
-#if defined(USE_JPWL) || defined(USE_MJ2)
-	img->comps[1].w = maxw; img->comps[1].h = maxh;
-	img->comps[2].w = maxw; img->comps[2].h = maxh;
-#else
-	img->comps[1].w = (OPJ_UINT32)maxw; img->comps[1].h = (OPJ_UINT32)maxh;
-	img->comps[2].w = (OPJ_UINT32)maxw; img->comps[2].h = (OPJ_UINT32)maxh;
-#endif
-	img->comps[1].dx = img->comps[0].dx;
-	img->comps[2].dx = img->comps[0].dx;
-	img->comps[1].dy = img->comps[0].dy;
-	img->comps[2].dy = img->comps[0].dy;
+	img->comps[1].w = img->comps[2].w = img->comps[0].w;
+	img->comps[1].h = img->comps[2].h = img->comps[0].h;
+	img->comps[1].dx = img->comps[2].dx = img->comps[0].dx;
+	img->comps[1].dy = img->comps[2].dy = img->comps[0].dy;
+	img->color_space = OPJ_CLRSPC_SRGB;
 	return;
 
 fails:
-	if(r) free(r);
-	if(g) free(g);
-	if(b) free(b);
-
+	free(r);
+	free(g);
+	free(b);
 }/* sycc422_to_rgb() */
 
 static void sycc420_to_rgb(opj_image_t *img)
 {
 	int *d0, *d1, *d2, *r, *g, *b, *nr, *ng, *nb;
 	const int *y, *cb, *cr, *ny;
-	unsigned int maxw, maxh, max;
+	size_t maxw, maxh, max, offx, loopmaxw, offy, loopmaxh;
 	int offset, upb;
-	unsigned int i, j;
+	size_t i;
 
 	upb = (int)img->comps[0].prec;
 	offset = 1<<(upb - 1); upb = (1<<upb)-1;
 
-	maxw = (unsigned int)img->comps[0].w; maxh = (unsigned int)img->comps[0].h;
+	maxw = (size_t)img->comps[0].w; maxh = (size_t)img->comps[0].h;
 	max = maxw * maxh;
 
 	y = img->comps[0].data;
 	cb = img->comps[1].data;
 	cr = img->comps[2].data;
 
-	d0 = r = (int*)malloc(sizeof(int) * (size_t)max);
-	d1 = g = (int*)malloc(sizeof(int) * (size_t)max);
-	d2 = b = (int*)malloc(sizeof(int) * (size_t)max);
-
-	if(r == NULL || g == NULL || b == NULL) goto fails;
-
-	for(i=0U; i < (maxh & ~(unsigned int)1U); i += 2U)
+	d0 = r = (int*)malloc(sizeof(int) * max);
+	d1 = g = (int*)malloc(sizeof(int) * max);
+	d2 = b = (int*)malloc(sizeof(int) * max);
+	
+	if (r == NULL || g == NULL || b == NULL) goto fails;
+	
+	/* if img->x0 is odd, then first column shall use Cb/Cr = 0 */
+	offx = img->x0 & 1U;
+	loopmaxw = maxw - offx;
+	/* if img->y0 is odd, then first line shall use Cb/Cr = 0 */
+	offy = img->y0 & 1U;
+	loopmaxh = maxh - offy;
+	
+	if (offy > 0U) {
+		size_t j;
+		
+		for(j=0; j < maxw; ++j)
+		{
+			sycc_to_rgb(offset, upb, *y, 0, 0, r, g, b);
+			++y; ++r; ++g; ++b;
+		}
+	}
+
+	for(i=0U; i < (loopmaxh & ~(size_t)1U); i += 2U)
 	{
+		size_t j;
+		
 		ny = y + maxw;
 		nr = r + maxw; ng = g + maxw; nb = b + maxw;
-
-		for(j=0; j < (maxw & ~(unsigned int)1U); j += 2U)
+		
+		if (offx > 0U) {
+			sycc_to_rgb(offset, upb, *y, 0, 0, r, g, b);
+			++y; ++r; ++g; ++b;
+			sycc_to_rgb(offset, upb, *ny, *cb, *cr, nr, ng, nb);
+			++ny; ++nr; ++ng; ++nb;
+		}
+
+		for(j=0; j < (loopmaxw & ~(size_t)1U); j += 2U)
 		{
 			sycc_to_rgb(offset, upb, *y, *cb, *cr, r, g, b);
 			++y; ++r; ++g; ++b;
@@ -230,31 +261,33 @@
 			sycc_to_rgb(offset, upb, *ny, *cb, *cr, nr, ng, nb);
 			++ny; ++nr; ++ng; ++nb; ++cb; ++cr;
 		}
+		if(j < loopmaxw)
+		{
+			sycc_to_rgb(offset, upb, *y, *cb, *cr, r, g, b);
+			++y; ++r; ++g; ++b;
+
+			sycc_to_rgb(offset, upb, *ny, *cb, *cr, nr, ng, nb);
+			++ny; ++nr; ++ng; ++nb; ++cb; ++cr;
+		}
+		y += maxw; r += maxw; g += maxw; b += maxw;
+	}
+	if(i < loopmaxh)
+	{
+		size_t j;
+		
+		for(j=0U; j < (maxw & ~(size_t)1U); j += 2U)
+		{
+			sycc_to_rgb(offset, upb, *y, *cb, *cr, r, g, b);
+
+			++y; ++r; ++g; ++b;
+
+			sycc_to_rgb(offset, upb, *y, *cb, *cr, r, g, b);
+
+			++y; ++r; ++g; ++b; ++cb; ++cr;
+		}
 		if(j < maxw)
 		{
 			sycc_to_rgb(offset, upb, *y, *cb, *cr, r, g, b);
-			++y; ++r; ++g; ++b;
-
-			sycc_to_rgb(offset, upb, *ny, *cb, *cr, nr, ng, nb);
-			++ny; ++nr; ++ng; ++nb; ++cb; ++cr;
-		}
-		y += maxw; r += maxw; g += maxw; b += maxw;
-	}
-	if(i < maxh)
-	{
-		for(j=0U; j < (maxw & ~(unsigned int)1U); j += 2U)
-		{
-			sycc_to_rgb(offset, upb, *y, *cb, *cr, r, g, b);
-
-			++y; ++r; ++g; ++b;
-
-			sycc_to_rgb(offset, upb, *y, *cb, *cr, r, g, b);
-
-			++y; ++r; ++g; ++b; ++cb; ++cr;
-		}
-		if(j < maxw)
-		{
-			sycc_to_rgb(offset, upb, *y, *cb, *cr, r, g, b);
 		}
 	}
 
@@ -262,24 +295,17 @@
 	free(img->comps[1].data); img->comps[1].data = d1;
 	free(img->comps[2].data); img->comps[2].data = d2;
 
-#if defined(USE_JPWL) || defined(USE_MJ2)
-	img->comps[1].w = maxw; img->comps[1].h = maxh;
-	img->comps[2].w = maxw; img->comps[2].h = maxh;
-#else
-	img->comps[1].w = (OPJ_UINT32)maxw; img->comps[1].h = (OPJ_UINT32)maxh;
-	img->comps[2].w = (OPJ_UINT32)maxw; img->comps[2].h = (OPJ_UINT32)maxh;
-#endif
-	img->comps[1].dx = img->comps[0].dx;
-	img->comps[2].dx = img->comps[0].dx;
-	img->comps[1].dy = img->comps[0].dy;
-	img->comps[2].dy = img->comps[0].dy;
+	img->comps[1].w = img->comps[2].w = img->comps[0].w;
+	img->comps[1].h = img->comps[2].h = img->comps[0].h;
+	img->comps[1].dx = img->comps[2].dx = img->comps[0].dx;
+	img->comps[1].dy = img->comps[2].dy = img->comps[0].dy;
+	img->color_space = OPJ_CLRSPC_SRGB;
 	return;
 
 fails:
-	if(r) free(r);
-	if(g) free(g);
-	if(b) free(b);
-
+	free(r);
+	free(g);
... (diff truncated)
```
