# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5477_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5477_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 392-432 of the vulnerable file.

		wc -= stride;
		do {
			REPEAT4(stride, wp[stride] += wp[0]; wp++)
			wc -= stride;
		} while (wc > 0);
	}
	return 1;
}

/*
 * Floating point predictor accumulation routine.
 */
static int
fpAcc(TIFF* tif, uint8* cp0, tmsize_t cc)
{
	tmsize_t stride = PredictorState(tif)->stride;
	uint32 bps = tif->tif_dir.td_bitspersample / 8;
	tmsize_t wc = cc / bps;
	tmsize_t count = cc;
	uint8 *cp = (uint8 *) cp0;
	uint8 *tmp = (uint8 *)_TIFFmalloc(cc);

    if(cc%(bps*stride)!=0)
    {
        TIFFErrorExt(tif->tif_clientdata, "fpAcc",
                     "%s", "cc%(bps*stride))!=0");
        return 0;
    }

	if (!tmp)
		return 0;

	while (count > stride) {
		REPEAT4(stride, cp[stride] =
                        (unsigned char) ((cp[stride] + cp[0]) & 0xff); cp++)
		count -= stride;
	}

	_TIFFmemcpy(tmp, cp0, cc);
	cp = (uint8 *) cp0;
	for (count = 0; count < wc; count++) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -409,7 +409,7 @@
 	tmsize_t wc = cc / bps;
 	tmsize_t count = cc;
 	uint8 *cp = (uint8 *) cp0;
-	uint8 *tmp = (uint8 *)_TIFFmalloc(cc);
+	uint8 *tmp;
 
     if(cc%(bps*stride)!=0)
     {
@@ -418,6 +418,7 @@
         return 0;
     }
 
+    tmp = (uint8 *)_TIFFmalloc(cc);
 	if (!tmp)
 		return 0;
 
@@ -640,7 +641,7 @@
 	tmsize_t wc = cc / bps;
 	tmsize_t count;
 	uint8 *cp = (uint8 *) cp0;
-	uint8 *tmp = (uint8 *)_TIFFmalloc(cc);
+	uint8 *tmp;
 
     if((cc%(bps*stride))!=0)
     {
@@ -648,6 +649,8 @@
                      "%s", "(cc%(bps*stride))!=0");
         return 0;
     }
+
+    tmp = (uint8 *)_TIFFmalloc(cc);
 	if (!tmp)
 		return 0;
 
@@ -722,6 +725,7 @@
     {
         TIFFErrorExt(tif->tif_clientdata, "PredictorEncodeTile",
                      "%s", "(cc0%rowsize)!=0");
+        _TIFFfree( working_copy );
         return 0;
     }
 	while (cc > 0) {
```
