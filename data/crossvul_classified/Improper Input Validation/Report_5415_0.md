# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5415_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5415_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 489-529 of the vulnerable file.

	unsigned int i;
	uint_fast8_t tmp;

	/* Eliminate compiler warning about unused variables. */
	cstate = 0;

	if (jpc_getuint16(in, &siz->caps) ||
	  jpc_getuint32(in, &siz->width) ||
	  jpc_getuint32(in, &siz->height) ||
	  jpc_getuint32(in, &siz->xoff) ||
	  jpc_getuint32(in, &siz->yoff) ||
	  jpc_getuint32(in, &siz->tilewidth) ||
	  jpc_getuint32(in, &siz->tileheight) ||
	  jpc_getuint32(in, &siz->tilexoff) ||
	  jpc_getuint32(in, &siz->tileyoff) ||
	  jpc_getuint16(in, &siz->numcomps)) {
		return -1;
	}
	if (!siz->width || !siz->height || !siz->tilewidth ||
	  !siz->tileheight || !siz->numcomps || siz->numcomps > 16384) {
		return -1;
	}
	if (!(siz->comps = jas_alloc2(siz->numcomps, sizeof(jpc_sizcomp_t)))) {
		return -1;
	}
	for (i = 0; i < siz->numcomps; ++i) {
		if (jpc_getuint8(in, &tmp) ||
		  jpc_getuint8(in, &siz->comps[i].hsamp) ||
		  jpc_getuint8(in, &siz->comps[i].vsamp)) {
			jas_free(siz->comps);
			return -1;
		}
		if (siz->comps[i].hsamp == 0 || siz->comps[i].hsamp > 255) {
			jas_eprintf("invalid XRsiz value %d\n", siz->comps[i].hsamp);
			jas_free(siz->comps);
			return -1;
		}
		if (siz->comps[i].vsamp == 0 || siz->comps[i].vsamp > 255) {
			jas_eprintf("invalid YRsiz value %d\n", siz->comps[i].vsamp);
			jas_free(siz->comps);
			return -1;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -508,6 +508,10 @@
 	  !siz->tileheight || !siz->numcomps || siz->numcomps > 16384) {
 		return -1;
 	}
+	if (siz->tilexoff >= siz->width || siz->tileyoff >= siz->height) {
+		jas_eprintf("all tiles are outside the image area\n");
+		return -1;
+	}
 	if (!(siz->comps = jas_alloc2(siz->numcomps, sizeof(jpc_sizcomp_t)))) {
 		return -1;
 	}
```
