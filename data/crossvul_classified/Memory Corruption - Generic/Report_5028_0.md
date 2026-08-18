# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5028_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5028_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 121-161 of the vulnerable file.

        return (Imaging) ImagingError_ValueError(
            "unsupported resampling filter"
            );
    }

    /* prepare for horizontal stretch */
    filterscale = scale = (float) imIn->xsize / xsize;

    /* determine support size (length of resampling filter) */
    support = filterp->support;

    if (filterscale < 1.0) {
        filterscale = 1.0;
    }

    support = support * filterscale;

    /* maximum number of coofs */
    kmax = (int) ceil(support) * 2 + 1;

    /* coefficient buffer */
    kk = malloc(xsize * kmax * sizeof(float));
    if ( ! kk)
        return (Imaging) ImagingError_MemoryError();

    xbounds = malloc(xsize * 2 * sizeof(int));
    if ( ! xbounds) {
        free(kk);
        return (Imaging) ImagingError_MemoryError();
    }

    for (xx = 0; xx < xsize; xx++) {
        k = &kk[xx * kmax];
        center = (xx + 0.5) * scale;
        ww = 0.0;
        ss = 1.0 / filterscale;
        xmin = (int) floor(center - support);
        if (xmin < 0)
            xmin = 0;
        xmax = (int) ceil(center + support);
        if (xmax > imIn->xsize)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -138,9 +138,21 @@
     /* maximum number of coofs */
     kmax = (int) ceil(support) * 2 + 1;
 
+    // check for overflow
+    if (kmax > 0 && xsize > SIZE_MAX / kmax)
+        return (Imaging) ImagingError_MemoryError();
+
+    // sizeof(float) should be greater than 0
+    if (xsize * kmax > SIZE_MAX / sizeof(float))
+        return (Imaging) ImagingError_MemoryError();
+
     /* coefficient buffer */
     kk = malloc(xsize * kmax * sizeof(float));
     if ( ! kk)
+        return (Imaging) ImagingError_MemoryError();
+
+    // sizeof(int) should be greater than 0 as well
+    if (xsize > SIZE_MAX / (2 * sizeof(int)))
         return (Imaging) ImagingError_MemoryError();
 
     xbounds = malloc(xsize * 2 * sizeof(int));
```
