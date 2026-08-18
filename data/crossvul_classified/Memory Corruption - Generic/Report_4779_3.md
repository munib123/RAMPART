# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 4779_3
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4779_3`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 242-282 of the vulnerable file.

    int attributed_ph, attributed_pv;
    int repeat_count, color_index, max_color_index = 2, background_color_index;
    int param[10];
    int sixel_palet[SIXEL_PALETTE_MAX];
    unsigned char *imbuf, *dmbuf;
    int imsx, imsy;
    int dmsx, dmsy;
    int y;

    posision_x = posision_y = 0;
    max_x = max_y = 0;
    attributed_pan = 2;
    attributed_pad = 1;
    attributed_ph = attributed_pv = 0;
    repeat_count = 1;
    color_index = 0;
    background_color_index = 0;

    imsx = 2048;
    imsy = 2048;
    imbuf = (unsigned char *) AcquireQuantumMemory(imsx * imsy,1);

    if (imbuf == NULL) {
        return(MagickFalse);
    }

    for (n = 0; n < 16; n++) {
        sixel_palet[n] = sixel_default_color_table[n];
    }

    /* colors 16-231 are a 6x6x6 color cube */
    for (r = 0; r < 6; r++) {
        for (g = 0; g < 6; g++) {
            for (b = 0; b < 6; b++) {
                sixel_palet[n++] = SIXEL_RGB(r * 51, g * 51, b * 51);
            }
        }
    }
    /* colors 232-255 are a grayscale ramp, intentionally leaving out */
    for (i = 0; i < 24; i++) {
        sixel_palet[n++] = SIXEL_RGB(i * 11, i * 11, i * 11);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -259,7 +259,7 @@
 
     imsx = 2048;
     imsy = 2048;
-    imbuf = (unsigned char *) AcquireQuantumMemory(imsx * imsy,1);
+    imbuf = (unsigned char *) AcquireQuantumMemory(imsx , imsy);
 
     if (imbuf == NULL) {
         return(MagickFalse);
@@ -286,7 +286,7 @@
         sixel_palet[n] = SIXEL_RGB(255, 255, 255);
     }
 
-    (void) ResetMagickMemory(imbuf, background_color_index, imsx * imsy);
+    (void) ResetMagickMemory(imbuf, background_color_index, (size_t) imsx * imsy);
 
     while (*p != '\0') {
         if ((p[0] == '\033' && p[1] == 'P') || *p == 0x90) {
@@ -360,14 +360,14 @@
             if (imsx < attributed_ph || imsy < attributed_pv) {
                 dmsx = imsx > attributed_ph ? imsx : attributed_ph;
                 dmsy = imsy > attributed_pv ? imsy : attributed_pv;
-                dmbuf = (unsigned char *) AcquireQuantumMemory(dmsx * dmsy,1);
+                dmbuf = (unsigned char *) AcquireQuantumMemory(dmsx , dmsy);
                 if (dmbuf == (unsigned char *) NULL) {
                     imbuf = (unsigned char *) RelinquishMagickMemory(imbuf);
                     return (MagickFalse);
                 }
-                (void) ResetMagickMemory(dmbuf, background_color_index, dmsx * dmsy);
+                (void) ResetMagickMemory(dmbuf, background_color_index, (size_t) dmsx * dmsy);
                 for (y = 0; y < imsy; ++y) {
-                    (void) CopyMagickMemory(dmbuf + dmsx * y, imbuf + imsx * y, imsx);
+                    (void) CopyMagickMemory(dmbuf + dmsx * y, imbuf + (size_t) imsx * y, imsx);
                 }
                 imbuf = (unsigned char *) RelinquishMagickMemory(imbuf);
                 imsx = dmsx;
@@ -434,14 +434,14 @@
 
                 dmsx = nx;
                 dmsy = ny;
-                dmbuf = (unsigned char *) AcquireQuantumMemory(dmsx * dmsy,1);
+                dmbuf = (unsigned char *) AcquireQuantumMemory(dmsx , dmsy);
                 if (dmbuf == (unsigned char *) NULL) {
                     imbuf = (unsigned char *) RelinquishMagickMemory(imbuf);
                     return (MagickFalse);
                 }
-                (void) ResetMagickMemory(dmbuf, background_color_index, dmsx * dmsy);
+                (void) ResetMagickMemory(dmbuf, background_color_index, (size_t) dmsx * dmsy);
                 for (y = 0; y < imsy; ++y) {
-                    (void) CopyMagickMemory(dmbuf + dmsx * y, imbuf + imsx * y, imsx);
+                    (void) CopyMagickMemory(dmbuf + dmsx * y, imbuf + (size_t) imsx * y, imsx);
                 }
                 imbuf = (unsigned char *) RelinquishMagickMemory(imbuf);
                 imsx = dmsx;
@@ -484,7 +484,7 @@
                                 c <<= 1;
                             }
                             for (y = posision_y + i; y < posision_y + i + n; ++y) {
-                                (void) ResetMagickMemory(imbuf + imsx * y + posision_x, color_index, repeat_count);
+                                (void) ResetMagickMemory(imbuf + (size_t) imsx * y + posision_x, color_index, repeat_count);
                             }
                             if (max_x < (posision_x + repeat_count - 1)) {
                                 max_x = posision_x + repeat_count - 1;
@@ -517,7 +517,7 @@
     if (imsx > max_x || imsy > max_y) {
         dmsx = max_x;
         dmsy = max_y;
-        if ((dmbuf = (unsigned char *) AcquireQuantumMemory(dmsx * dmsy,1)) == NULL) {
+        if ((dmbuf = (unsigned char *) AcquireQuantumMemory(dmsx , dmsy)) == NULL) {
             imbuf = (unsigned char *) RelinquishMagickMemory(imbuf);
             return (MagickFalse);
         }
@@ -1298,7 +1298,7 @@
     Define SIXEL pixels.
   */
   output = sixel_output_create(image);
-  sixel_pixels =(unsigned char *) AcquireQuantumMemory(image->columns * image->rows,1);
+  sixel_pixels =(unsigned char *) AcquireQuantumMemory(image->columns , image->rows);
   for (y=0; y < (ssize_t) image->rows; y++)
   {
     (void) GetVirtualPixels(image,0,y,image->columns,1,exception);
```
