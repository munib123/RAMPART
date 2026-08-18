# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5062_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5062_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 838-878 of the vulnerable file.

		if(red) free(red);
		if(green) free(green);
		if(blue) free(blue);
		return;
	}
	
	fprintf(stderr,"%s:%d:\n\tenumCS %d not handled. Ignoring.\n", __FILE__,__LINE__, enumcs);
}/* color_cielab_to_rgb() */

#endif /* OPJ_HAVE_LIBLCMS2 || OPJ_HAVE_LIBLCMS1 */

void color_cmyk_to_rgb(opj_image_t *image)
{
	float C, M, Y, K;
	float sC, sM, sY, sK;
	unsigned int w, h, max, i;

	w = image->comps[0].w;
	h = image->comps[0].h;

	if(image->numcomps < 4) return;

	max = w * h;
	
	sC = 1.0F / (float)((1 << image->comps[0].prec) - 1);
	sM = 1.0F / (float)((1 << image->comps[1].prec) - 1);
	sY = 1.0F / (float)((1 << image->comps[2].prec) - 1);
	sK = 1.0F / (float)((1 << image->comps[3].prec) - 1);

	for(i = 0; i < max; ++i)
	{
		/* CMYK values from 0 to 1 */
		C = (float)(image->comps[0].data[i]) * sC;
		M = (float)(image->comps[1].data[i]) * sM;
		Y = (float)(image->comps[2].data[i]) * sY;
		K = (float)(image->comps[3].data[i]) * sK;
		
		/* Invert all CMYK values */
		C = 1.0F - C;
		M = 1.0F - M;
		Y = 1.0F - Y;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -855,7 +855,14 @@
 	w = image->comps[0].w;
 	h = image->comps[0].h;
 
-	if(image->numcomps < 4) return;
+	if (
+			(image->numcomps < 4)
+		 || (image->comps[0].dx != image->comps[1].dx) || (image->comps[0].dx != image->comps[2].dx) || (image->comps[0].dx != image->comps[3].dx)
+		 || (image->comps[0].dy != image->comps[1].dy) || (image->comps[0].dy != image->comps[2].dy) || (image->comps[0].dy != image->comps[3].dy)
+			) {
+		fprintf(stderr,"%s:%d:color_cmyk_to_rgb\n\tCAN NOT CONVERT\n", __FILE__,__LINE__);
+		return;
+	}
 
 	max = w * h;
 	
```
