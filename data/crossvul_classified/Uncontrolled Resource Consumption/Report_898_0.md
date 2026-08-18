# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 898_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `898_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 605-645 of the vulnerable file.

                    c = getc(IN);
                    if (c == EOF) {
                        return OPJ_FALSE;
                    }
                }
            }
        }
    }/* while() */

    if (written != width * height) {
        fprintf(stderr, "warning, image's actual size does not match advertized one\n");
        return OPJ_FALSE;
    }

    return OPJ_TRUE;
}

static OPJ_BOOL bmp_read_rle4_data(FILE* IN, OPJ_UINT8* pData,
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
            break;
        }

        if (c) { /* encoded mode */
            int j;
            OPJ_UINT8 c1 = (OPJ_UINT8)getc(IN);

            for (j = 0; (j < c) && (x < width) &&
                    ((OPJ_SIZE_T)pix < (OPJ_SIZE_T)beyond); j++, x++, pix++) {
                *pix = (OPJ_UINT8)((j & 1) ? (c1 & 0x0fU) : ((c1 >> 4) & 0x0fU));
            }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -622,13 +622,13 @@
 static OPJ_BOOL bmp_read_rle4_data(FILE* IN, OPJ_UINT8* pData,
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
@@ -642,6 +642,7 @@
             for (j = 0; (j < c) && (x < width) &&
                     ((OPJ_SIZE_T)pix < (OPJ_SIZE_T)beyond); j++, x++, pix++) {
                 *pix = (OPJ_UINT8)((j & 1) ? (c1 & 0x0fU) : ((c1 >> 4) & 0x0fU));
+                written++;
             }
         } else { /* absolute mode */
             c = getc(IN);
@@ -671,6 +672,7 @@
                         c1 = (OPJ_UINT8)getc(IN);
                     }
                     *pix = (OPJ_UINT8)((j & 1) ? (c1 & 0x0fU) : ((c1 >> 4) & 0x0fU));
+                    written++;
                 }
                 if (((c & 3) == 1) || ((c & 3) == 2)) { /* skip padding byte */
                     getc(IN);
@@ -678,6 +680,10 @@
             }
         }
     }  /* while(y < height) */
+    if (written != width * height) {
+        fprintf(stderr, "warning, image's actual size does not match advertized one\n");
+        return OPJ_FALSE;
+    }
     return OPJ_TRUE;
 }
 
```
