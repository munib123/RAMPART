# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 897_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `897_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 517-557 of the vulnerable file.

    }
    return OPJ_TRUE;
}

static OPJ_BOOL bmp_read_raw_data(FILE* IN, OPJ_UINT8* pData, OPJ_UINT32 stride,
                                  OPJ_UINT32 width, OPJ_UINT32 height)
{
    OPJ_ARG_NOT_USED(width);

    if (fread(pData, sizeof(OPJ_UINT8), stride * height, IN) != (stride * height)) {
        fprintf(stderr,
                "\nError: fread return a number of element different from the expected.\n");
        return OPJ_FALSE;
    }
    return OPJ_TRUE;
}

static OPJ_BOOL bmp_read_rle8_data(FILE* IN, OPJ_UINT8* pData,
                                   OPJ_UINT32 stride, OPJ_UINT32 width, OPJ_UINT32 height)
{
    OPJ_UINT32 x, y;
    OPJ_UINT8 *pix;
    const OPJ_UINT8 *beyond;

    beyond = pData + stride * height;
    pix = pData;

    x = y = 0U;
    while (y < height) {
        int c = getc(IN);
        if (c == EOF) {
            return OPJ_FALSE;
        }

        if (c) {
            int j, c1_int;
            OPJ_UINT8 c1;

            c1_int = getc(IN);
            if (c1_int == EOF) {
                return OPJ_FALSE;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -534,14 +534,14 @@
 static OPJ_BOOL bmp_read_rle8_data(FILE* IN, OPJ_UINT8* pData,
                                    OPJ_UINT32 stride, OPJ_UINT32 width, OPJ_UINT32 height)
 {
-    OPJ_UINT32 x, y;
+    OPJ_UINT32 x, y, written;
     OPJ_UINT8 *pix;
     const OPJ_UINT8 *beyond;
 
     beyond = pData + stride * height;
     pix = pData;
 
-    x = y = 0U;
+    x = y = written = 0U;
     while (y < height) {
         int c = getc(IN);
         if (c == EOF) {
@@ -561,6 +561,7 @@
             for (j = 0; (j < c) && (x < width) &&
                     ((OPJ_SIZE_T)pix < (OPJ_SIZE_T)beyond); j++, x++, pix++) {
                 *pix = c1;
+                written++;
             }
         } else {
             c = getc(IN);
@@ -598,6 +599,7 @@
                     }
                     c1 = (OPJ_UINT8)c1_int;
                     *pix = c1;
+                    written++;
                 }
                 if ((OPJ_UINT32)c & 1U) { /* skip padding byte */
                     c = getc(IN);
@@ -608,6 +610,12 @@
             }
         }
     }/* while() */
+
+    if (written != width * height) {
+        fprintf(stderr, "warning, image's actual size does not match advertized one\n");
+        return OPJ_FALSE;
+    }
+
     return OPJ_TRUE;
 }
 
```
